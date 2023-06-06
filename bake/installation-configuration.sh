#!/usr/bin/env bash
set -euoE pipefail ## -E option will cause functions to inherit trap

echo "Reconfiguring single node OpenShift"

function mount_config {
  echo "Mounting config iso"
  mkdir /mnt/config
  mount /dev/$1 /mnt/config
  ls /mnt/config
}

function umount_config {
  echo "Unmounting config iso"
  umount /dev/$1
  rm -rf /mnt/config
}

CONFIGURATION_FILE=/opt/openshift/site-config.env
echo "Waiting for ${CONFIGURATION_FILE}"
while [[ ! $(lsblk -f --json | jq -r '.blockdevices[] | select(.label == "ZTC SNO") | .name') && ! -f /opt/openshift/site-config.env ]]; do echo hi;  sleep 5; donedo
  sleep 5
done

DEVICE=$(lsblk -f --json | jq -r '.blockdevices[] | select(.label == "ZTC SNO") | .name')
if [[ -n ${DEVICE+x} ]]; then
  mount_config "${DEVICE}"
  cp /mnt/config/site-config.env ${CONFIGURATION_FILE}
fi

if [ ! -f "${CONFIGURATION_FILE}" ]; then
  echo "Failed to find configuration file at ${CONFIGURATION_FILE}"
  exit 1
fi

echo "${CONFIGURATION_FILE} has been created"

set -o allexport
source ${CONFIGURATION_FILE}
set +o allexport


if [ -z ${CLUSTER_NAME+x} ]; then
	echo "Please set CLUSTER_NAME"
	exit 1
fi

if [ -z ${BASE_DOMAIN+x} ]; then
	echo "Please set BASE_DOMAIN"
	exit 1
fi

# TODO: Update hostname
# TODO: update IP address, machine network
# TODO: Regenerate/update certificates

echo "Starting kubelet"
systemctl start kubelet

#TODO: we need to add kubeconfig to the node for the configuration stage
export KUBECONFIG=/etc/kubernetes/static-pod-resources/kube-apiserver-certs/secrets/node-kubeconfigs/localhost.kubeconfig
function wait_for_api {
  echo "Waiting for api ..."
  until oc get clusterversion &> /dev/null
  do
    echo "Waiting for api ..."
    sleep 5
  done
  echo "api is available"
}

wait_for_api

# Reconfigure DNS

node_ip=$(oc get nodes -o jsonpath='{.items[0].status.addresses[?(@.type == "InternalIP")].address}')

log_info "Updating dnsmasq with new domain"
cat << EOF > /etc/dnsmasq.d/customer-domain.conf
address=/apps.${CLUSTER_NAME}.${BASE_DOMAIN}/${node_ip}
address=/api-int.${CLUSTER_NAME}.${BASE_DOMAIN}/${node_ip}
address=/api.${CLUSTER_NAME}.${BASE_DOMAIN}/${node_ip}
EOF
systemctl restart dnsmasq

create_cert(){
  local secret_name=${1}
  local domain_name=${2}
  local namespace=${3:-"openshift-config"}

  if [ ! -f $secret_name.done ]
  then
    echo "Creating new cert for $domain_name"
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout /tmp/key-"${secret_name}".pem -out /tmp/cert-"${secret_name}".pem \
    -subj "/CN=${domain_name}" -addext "subjectAltName = DNS:${domain_name}"
    touch "${secret_name}".done
  fi
  oc create secret tls "${secret_name}"-tls --cert=/tmp/cert-"${secret_name}".pem --key=/tmp/key-"${secret_name}".pem -n $namespace --dry-run=client -o yaml | oc apply -f -
}

wait_for_cert() {
    NEW_CERT=$(cat "${1}")
    log_info "Waiting for ${2} cert to update"
    SERVER_CERT=$(echo | timeout 5 openssl s_client -showcerts -connect "${2}":"${3}" 2>/dev/null | openssl x509 || true)
    log_info "Waiting for cert to update"
    until [[ "${NEW_CERT}" == "${SERVER_CERT}" ]]
    do
        sleep 10
        SERVER_CERT=$(echo | timeout 5 openssl s_client -showcerts -connect "${2}":"${3}" 2>/dev/null | openssl x509 || true)
    done

    wait_for_co
}

SITE_DOMAIN="${CLUSTER_NAME}.${BASE_DOMAIN}"
API_DOMAIN="api.${SITE_DOMAIN}"
APPS_DOMAIN="apps.${SITE_DOMAIN}"
CONSOLE_DOMAIN="console-openshift-console.${APPS_DOMAIN}"
DOWNLOADS_DOMAIN="downloads-openshift-console.${APPS_DOMAIN}"
OAUTH_DOMAIN="oauth-openshift.${APPS_DOMAIN}"

echo "Update API"
create_cert "api" "${API_DOMAIN}"

# Patch the apiserver
envsubst << "EOF" >> api.patch
spec:
  servingCerts:
    namedCertificates:
    - names:
      - api.${CLUSTER_NAME}.${BASE_DOMAIN}
      servingCertificate:
        name: api-tls
EOF

oc patch apiserver cluster --patch-file api.patch --type=merge

# TODO: check that API got updated
wait_for_cert /tmp/cert-api.pem "${API_DOMAIN}" 6443

create_cert "apps" "*.${APPS_DOMAIN}"
create_cert "apps" "*.${APPS_DOMAIN}" openshift-ingress

echo "Update ingress"
envsubst << "EOF" >> domain.patch
spec:
  appsDomain: ${APPS_DOMAIN}
  componentRoutes:
  - hostname: ${CONSOLE_DOMAIN}
    name: console
    namespace: openshift-console
    servingCertKeyPairSecret:
      name: apps-tls
  - hostname: ${DOWNLOADS_DOMAIN}
    name: downloads
    namespace: openshift-console
    servingCertKeyPairSecret:
      name: apps-tls
  - hostname: ${OAUTH_DOMAIN}
    name: oauth-openshift
    namespace: openshift-authentication
    servingCertKeyPairSecret:
      name: apps-tls
EOF

oc patch ingress.config.openshift.io cluster --patch-file domain.patch --type merge

wait_for_cert "${APPS_CERT_FILE_PATH}" "${CONSOLE_DOMAIN}" 443

log_info "Re-configuring existing Routes"
# They will get recreated by the relevant operator
oc delete routes --field-selector metadata.namespace!=openshift-console,metadata.namespace!=openshift-authentication -A

# TODO: Update ssh-key?

echo "Configure cluster registry"
# see https://docs.openshift.com/container-platform/4.12/post_installation_configuration/connected-to-disconnected.html#connected-to-disconnected-config-registry_connected-to-disconnected
# we need to do 5 things:
# Create a ConfigMap with the certificate for the registry
# Reference that ConfigMap in image.config.openshift.io/cluster (spec/additionalTrustedCA)
# Update the cluster pull-secret
# Create an ImageContentSourcePolicy
# Create a CatalogSource
# TODO validate we have all required fields
# TODO: should we verify the pull secret is valid? how?

if [ -z ${PULL_SECRET+x} ]; then
	echo "PULL_SECRET not defined"
else
  log_info 'Updating cluster-wide pull secret'
  echo "${PULL_SECRET}" > ps.json
  oc set data secret/pull-secret -n openshift-config --from-file=.dockerconfigjson=ps.json
fi

if [ -z ${REGISTRY_CA+x} ]; then
	echo "REGISTRY_CA not defined"
else
  log_info 'Creating ConfigMap with registry certificate'
  echo "${REGISTRY_CA}" > ps.json
  oc create configmap edge-registry-config --from-file="edge-registry-ca.crt" -n openshift-config --dry-run=client -o yaml | oc apply -f -

  log_info 'Adding certificate to Image additionalTrustedCA'
  oc patch image.config.openshift.io/cluster --patch '{"spec":{"additionalTrustedCA":{"name":"edge-registry-config"}}}' --type=merge
fi

if [ -z ${REGISTRY_URL+x} ]; then
	echo "REGISTRY_URL not defined"
else

  log_info 'Creating ImageContentSourcePolicy'
  cat << EOF | oc apply -f -
apiVersion: operator.openshift.io/v1alpha1
kind: ImageContentSourcePolicy
metadata:
  name: mirror-ocp
spec:
  repositoryDigestMirrors:
  - mirrors:
    - ${REGISTRY_URL}/openshift/release
    source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
  - mirrors:
    - ${registry_url}/openshift/release-images
    source: quay.io/openshift-release-dev/ocp-release
  - mirrors:
    - ${REGISTRY_URL}/multicluster-engine
    source: registry.redhat.io/multicluster-engine
  - mirrors:
    - ${REGISTRY_URL}/redhat
    source: registry.redhat.io/redhat
  - mirrors:
    - ${REGISTRY_URL}/rhel8
    source: registry.redhat.io/rhel8
  - mirrors:
    - ${REGISTRY_URL}/rhacm2
    source: registry.redhat.io/rhacm2
  - mirrors:
    - ${REGISTRY_URL}/openshift4
    source: registry.redhat.io/openshift4
EOF

fi

rm -rf /opt/openshift
systemctl enable kubelet
systemctl disable installation-configuration.service
if [[ -n ${DEVICE+x} ]]; then
  umount_config "${DEVICE}"
fi
