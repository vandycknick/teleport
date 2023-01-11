# Teleport Usage Gathering Script

This script retrieves the number of unique users accessing each of the five Teleport supported protocols.

## Prerequisites

This tool requires a Teleport cluster running with AWS DynamoDB as your backend server. This script runs as a docker container from either the auth server or a server with IAM permissions necessary to run queres on the DynamoDB events table. 

The following information is required:

| Env Variable | Description |
| ---------|-------------|
| TABLE_NAME | DynamoDB Events Table Name |
| AWS_REGION | AWS Region where the dynamoDB table is deployed |
| START_DATE | The date for when to start the query. The format must be YYYY-MM-DD |
| END_DATE | The date for when you want the query to end. The format must be YYYY-MM-DD |

## Running Docker Container

With prompt:

```console
$ docker run -it --rm public.ecr.aws/gravitational/teleport-usage:<VERSION>
```

With environment variables:

```console
$ docker run -it --rm public.ecr.aws/gravitational/teleport-usage:<VERSION> \
-e “TABLE_NAME=cluster-events” -e “AWS_REGION=us-east-1” \
-e “START_DATE=2022-12-01” -e “END_DATE=2023-01-01”
```

## Running on Kubernetes

```console
$ kubectl run -it --rm --image=public.ecr.aws/gravitational/teleport-usage:<VERSION> --env="TABLE_NAME=teleport-demo-events" --env="AWS_REGION=us-east-1" --env="START_DATE=2022-12-01" --env="END_DATE=2023-01-01" teleport-usage
```
