# prowler-lambda-worker

The prowler-lambda-worker is a AWS Lambda compromising of a Docker image.

It is responsible for executing the open source project prowler which scans an
AWS environment defined at the account level against a set of rules that can be
grouped into defined groups.

This lambda is executed by the [prowler
manager](https://github.com/jezd-axyl/prowler-lambda-manager).

AWS accounts on the Platform need to be benchmarked for security compliance on a
scheduled basis. Infrastructure that is not compliant needs to be reported to
the Teams that own the accounts for remediation. Prowler is an open source tool
that tests an AWS account against a set of security and compliance checks that
have been written in Bash. The checks are then grouped together in pre-defined
groups. Currently, there are twenty one groups covering common standards such
as:

* HIPAA
* SOC
* CIS

As well as more specific technology area groupings around:

* Networking
* RDS (Relational Database Service)
* SageMaker

This solution will deliver the capability of scheduled checks against MDTP’s AWS
infrastructure highlighting issues, concerns and best practices against well
defined benchmarks. This project allows for teams to create their own custom
checks. A check is essentially a Bash script that executes API calls against the AWS cloud platform.
Please note that if you are creating your own groups the file must have the
following run against it `chmod 664 <file_name>`.

## Getting Started

These instructions will get you a copy of the project up and running on your
local machine for development and testing purposes. See deployment for notes on
how to deploy the project on a live system.

### Prerequisites

You will need the following installed on your machine:

GNU Make
Python version >= 3.8.x
Pipenv

### Installing

Prowler has to be installed by `./install_prowler` which will put it in the
right location for this Python library.

All Python dependencies are defined in the Pipfile in the root of the project,
run `pipenv install`.

### Running the tests

To run all tests, run `make test`.

### License

This code is open source software licensed under the [Apache 2.0
License]("http://www.apache.org/licenses/LICENSE-2.0.html").
