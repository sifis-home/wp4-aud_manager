# WP4 Analytic: AUD Sensor

This is the sensing part of AUD manager. While aud_manager is intended to run a on central network routing device, aud_sensor is intended to run inside any SIFIS-Home compliant smart device.


## Quickstart

Disclaimer: This is by no means a complete documentation. It is merely a collection of commands for demonstrative purposes.

### Preparations on the host system

#### 1. Insert necessary iptables rules

`sudo ./aud_control.sh iptables add`

#### 2. Create necessary paths

`mkdir -p /tmp/aud`

#### 3. Build and execute the data intake module

`cd modules/nflog_connector`
`make clean && make`
`sudo ./nflog`

### AUD Sensor in a container

#### 1. Build the container

`docker build -t aud_sensor -f docker-files/Dockerfile-aud_sensor .`

#### 2. Start the docker

`docker run -d --cap-add NET_ADMIN --net host --privileged --mount type=bind,source="/tmp/aud",target="/tmp/aud" --name aud_sensor aud_sensor`

#### 3. Test if it runs and its API replies

`curl localhost:5050/status`

If yes, then carry on...

#### 4. Start the internal operation of aud_sensor

`curl localhost:5050/start`

After this you can verify that the `running` status has change to `True` with the status endpoint listed above. If all is good and it is running, then all network activity performed from now on is considered as training data to the analytic. At this point you may want to perform some arbitrary network tasks just to give some input to the analytic. Once done, you may continue to the next step.

#### 5. Stop the learning phase of the analytic

`curl localhost:5050/dev/force-stop-learning`

Note: The API endpoints prefixed with `/dev/` are meant for development purposes.

#### 6. Manually perform a mock anomaly

Now that the learning phase has been stopped, any network flows except the ones instigated during the learning phase, will be queued for anomaly verdict. Such an incident can be confirmed through the built in log:

`curl localhost:5050/log`

There is a slight delay (max 10 seconds) between executing a mock anomaly and the log entry showing up.
