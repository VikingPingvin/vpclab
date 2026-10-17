#!/usr/bin/env bash
# Terminate every instance in Floci and reconcile, which removes all vpcsim
# containers. VPC, subnet and SG records stay in Floci.
set -euo pipefail
cd "$(dirname "$0")/../.."

aws() {
  docker run --rm --network host -e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test \
    -e AWS_DEFAULT_REGION=us-east-1 amazon/aws-cli --endpoint-url http://localhost:4566 "$@"
}
ids=$(aws ec2 describe-instances --filters Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].InstanceId' --output text)
if [[ -n "$ids" ]]; then
  aws ec2 terminate-instances --instance-ids $ids --output text >/dev/null
  echo "terminated: $ids"
fi
bash scripts/vpcsim.sh apply
