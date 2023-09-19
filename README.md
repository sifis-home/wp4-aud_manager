# WP4 Analytic: AUD Manager

[![Actions Status][actions badge]][actions]
[![CodeCov][codecov badge]][codecov]
[![LICENSE][license badge]][license]

<!-- Links -->
[actions]: https://github.com/sifis-home/wp4-aud_manager/actions
[codecov]: https://codecov.io/gh/sifis-home/wp4-aud_manager
[license]: LICENSES/MIT.txt

<!-- Badges -->
[actions badge]: https://github.com/sifis-home/wp4-aud_manager/workflows/wp4-aud_manager/badge.svg
[codecov badge]: https://codecov.io/gh/sifis-home/wp4-aud_manager/branch/master/graph/badge.svg
[license badge]: https://img.shields.io/badge/license-MIT-blue.svg


## Deploying

### AUD Manager in a container

AUD Manager is intended to run in a docker container. The Dockerfile at the root of this repo describes the container. To fetch the latest container image from `ghcr.io` and run it execute the following:

`docker-compose up`

For developement purposes one may want to build and run the container locally. To do that use the enclosed wrapper script as follows:

`./local_run.sh docker`


## REST API of AUD Manager

Description of the various REST endpoint available while AUD Manager is running.

---

#### GET /status

Description: Return the status of the currently running analytic, including a summary of recenty anomalies.

Sample: `curl http://localhost:5050/status`

---

#### GET /log

Description: List of logged events.

Sample: `curl http://localhost:5050/log`

---

#### GET /mark-benign/{anomaly_uuid}|all

Description: Mark anomaly with provided UUID as benign. One can also use `all` in place of a UUID to clear all current in-memory anomalies.

Sample: `curl http://localhost:5050/mark-benign/00000000-1234-1234-1234-123456789012`

---

## REST API endpoints for development use only

#### GET /dev/diag

Description: Verbose output of analytic internals. JSON schema of the output is volatile and subject to change as the analytic is being developed.

Sample: `curl http://localhost:5050/dev/diag`

---

#### GET /dev/aud-update

Description: Manually enforce an internal aud_update().

Sample: `curl http://localhost:5050/dev/aud-update`

---

#### GET /dev/connlist

Descriptiong: Returns a list of active connections on AUD managers internal connection tracking.

Sample: `curl http://localhost:5050/dev/connlist`
