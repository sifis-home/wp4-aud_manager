# WP4 Analytic: AUD Manager


## Deploying

### AUD Manager in a container

AUD Manager is intended to run in a docker container. The Dockerfile at the root of this repo describes the container. To fetch the latest container image from `ghcr.io` and run it execute the following:

`docker-compose up`

For developement purposes one may want to build and run the container locally. To do that use the enclosed wrapper script as follows:

`./local_run.sh docker`


## REST API of AUD Manager

Description of the various REST endpoint available while AUD Manager is running.

---

#### GET /start

Description: Start the internal network analytic.

Sample: `curl http://aud_manager:6060/start`

---

#### GET /stop

Description: Stop the internal network analytic.

Sample: `curl http://aud_manager:6060/stop`

---

#### GET /status

Description: Return the status of the currently running analytic, including a summary of recenty anomalies.

Sample: `curl http://aud_manager:6060/status`

---

#### GET /mark-benign/{anomaly_uuid}

Description: Stop the internal network analytic.

Sample: `curl http://aud_manager:6060/mark-benign/00000000-1234-1234-1234-123456789012`

---

## REST API endpoints for development use only

#### GET /dev/diag

Description: Verbose output of analytic internals. JSON schema of the output is volatile and subject to change as the analytic is being developed.

Sample: `curl http://aud_manager:6060/dev/diag`
