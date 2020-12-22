
# AWS IP inventory

Tool to generate an inventory of all IP addresses in use in an account, one or multiple VPC, or one or multiple subnet.

Features:

* Detects the object type that uses the interface (EC2, RDS, etc.); not always possible because this guess is done using some magic from the interface description.
* Filter by region, VPC and/or subnet
* Guess a friendly name of the object (EC2 Name tag, for example)
* Gets project and environment tags
* Multiple output formats
* Links to AWS web console for services/objects

Output formats:

* Console table
* HTML
* JSON
* YAML
* CSV

Supported services:

* [x] EC2 instances
* [x] ElastiCache (partially)
* [x] ELB/ALB (ELBv2)
* [x] RDS
* [x] ECS tasks
* [x] NAT Gateways
* [x] EFS mount targets
* [x] Directories
* [x] Workspaces
* [x] Lambda
* [x] CodeBuild (only service, not object)
* [x] API Gateway VPC link

Internally, the script gets the list of [network interfaces](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_network_interfaces),
and tries to guess to what service and object the interface is attached to; this is not always possible, because there is no a direct property
to know it, and this must be guessed using regexs and string comparison using the interface description or the requester property.

Keep in mind that some network interfaces are ephemeral, i.e. they live only for a short period of time, like the ones used in Lambda,
in ECS tasks, etc. Others have a longer life, like the ones used in "static" EC2 instances.

## Installation

Using [pip](https://pip.pypa.io/en/stable/):

```bash
pip install --user git+https://github.com/okelet/awsipinventory
```

Cloning the repository:

```bash
git clone https://github.com/okelet/awsipinventory
```

## Usage

```text
usage: __main__.py [-h] [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                   [-f {none,table,html,json,yaml,yml,csv}] [-o OUTPUT]
                   [--regions [REGIONS [REGIONS ...]]]
                   [--vpcs [VPCS [VPCS ...]]]
                   [--subnets [SUBNETS [SUBNETS ...]]]
                   [--columns [COLUMNS [COLUMNS ...]]]

optional arguments:
  -h, --help            show this help message and exit
  -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level
  -f {none,table,html,json,yaml,yml,csv}, --format {none,table,html,json,yaml,yml,csv}
                        Output format
  -o OUTPUT, --output OUTPUT
                        Output file; defaults to standard output
  --regions [REGIONS [REGIONS ...]]
                        Use "all" to get data from all enabled regions
  --vpcs [VPCS [VPCS ...]]
                        Restrict results to specific VPCs (must exist in the
                        account and regions)
  --subnets [SUBNETS [SUBNETS ...]]
                        Restrict results to specific subnets (must exist in
                        the account, VPCs and regions)
  --columns [COLUMNS [COLUMNS ...]]
```

Running from an standard Linux:

```bash
awsipinventory --format html --output /tmp/inventory.html && firefox /tmp/inventory.html
```

Running from WSL:

```bash
ln -s /mnt/c/Program\ Files/Mozilla\ Firefox/firefox.exe ~/.local/bin/firefox
awsipinventory --format html --output /tmp/inventory.html && firefox $(wslpath -w /tmp/inventory.html)
```

From local development environment or cloned repository:

```bash
pipenv run python -m awsipinventory
```

## Testing package deployment

Set credential environment variables manually, or using another tool, like [AWSume](https://github.com/trek10inc/awsume); then test the application
using Docker directly:

```bash
docker build -t awsipinventory:latest .
docker run -it --rm -e AWS_DEFAULT_REGION -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN awsipinventory:latest --log-level debug -f json
```

Or using `docker-compose`:

```bash
awsume xxx
docker-compose up --build --force-recreate
docker-compose rm -fs
```
