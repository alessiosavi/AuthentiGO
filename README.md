
# AuthentiGo

[![Build Status](https://travis.ibm.com/Alessio-Savi/GoLogAnalyzer.svg?token=wWmbVrxsSXYSyYLLhamH&branch=master)](https://travis.ibm.com/Alessio-Savi/GoLogAnalyzer)

Simple Golang tool that work as a "plug-and-play" executable for authenticate your webapplication

## Getting Started

During the development of every internal tools, 90% of the time it's request to create an "__*authentication layer*__" in order to restrict the access to the services only to the person admitted.

In some circonstances you can simply pick up an external webserver (like *nginx/apache/happroxy*) and *proxypass/reroute* the service. If you are the root of the machine you can also forward the traffic only to the people admitted to receive it by *forwarding* the TCP traffic only to the customer allowed.

But what in case that you are a little IT Specials that *can't touch the enviroinment* and *want to restrict the access to a service using an __authentication layer__*?

Taaa dan!

This tool is developed for have few HTTP API interfaces in order:

- Registration layer for save customers into a database;
- Login layer in order to get access to the services to the customer that have previously registered;
- Restrict access to the service only for the customer that are allowed;

### Features

- Login phase:

    -- Purpouse:

        1) Auth is needed in order to receive the token;
        2) Retrict the access
    -- Capabilites:

        * *Input valdation methods*
        * *BasicAuth headers welcome*
        * *Verify if user match with the one in MongoDB*
        * *Generate token and set it into Redis*
- Registration

    -- Purpouse:

        1) Save the user that can access to the services
    -- Capabilities:

        * *Input valdation methods*
        * *BasicAuth headers welcome*
        * *Persistent data saved into MongoDB*

- Verification

    -- Purpouse:

        1) Create a middleware for "proxypass" the request
        2) Verify the authentication of every request
        3) Be as much "standard" as possibile in order to be used without integration issue
        4) Have a performing verification layer that can be scaled @runtime
    -- Capabilites:

        * *RESTfull implementation*
        * *Input valdation methods*
        * *Redis authentication for great performance*

The tool is intended to:

- Run only on Linux machine (*test on windows is appreciated*);
- Bind the necessary network resources over a network device that can expose data to the network (ex: 0.0.0.0);
- Consume as much low memory as possible (gzip data if request by the client);
- Be scalable;
- Don't steal time to the request

During the development of the source code, I'll will try as much as i can to write modular function that can be replaced or swapped. Feel free to copy and paste the code without ask, but please license your code as a MIT licensed software

## Prerequisites

The installation process is described only for __*Linux*__ machine.

The software is coded in:

- Golang

The software use two different database:

- MongoDB
    -- Used for store the data of the customer;
- Redis
    -- Used for store the token of the customer in order to speed up the authentication process;

For run the software you need:

1) Golang
2) MongoDB
3) Redis-Server

### 1) Install Golang

In order to install golang in your machine, you have to run the following commands:

- NOTE:
  - It's preferable __*to don't run these command as root*__. Simply *`chown`* the *`root_foolder`* of golang to be compliant with your user and run the script.
  - Run this "installer" script only once

```bash

golang_version="1.11.4"
golang_link="https://dl.google.com/go/go$golang_version.linux-amd64.tar.gz"
root_foolder="/opt/GOLANG" # Set the tree variable needed for build the enviroinment
go_source="$root_foolder/go"
go_projects="$root_foolder/go_projects"

mkdir $root_foolder # creating dir for golang source code
cd $root_foolder # entering dir
wget $golang_link #downloading golang
tar xf $(ls | grep "tar") # extract only the tar file
mkdir go_projects

echo '
export GOPATH="$go_projects"
export GOBIN="$GOPATH/bin"
export GOROOT="$go_source"
export PATH="$PATH:$GOROOT/bin:$GOBIN"
' >> /home/$(whoami)/.bashrc

source /home/$(whoami)/.bashrc

go version
```

After running these command, you have to be able to see the golang version installed.

### 2) Install MongoDB

In order to install MongoDB (and some related usefull utils), you have to run the following commands:

__*The following operations have to be done as root*__

```bash
mkdir /opt/MongoDB
cd $_
wget https://repo.mongodb.org/yum/redhat/7/mongodb-org/4.0/x86_64/RPMS/mongodb-org-server-4.0.5-1.el7.x86_64.rpm
wget https://repo.mongodb.org/yum/redhat/7/mongodb-org/4.0/x86_64/RPMS/mongodb-org-tools-4.0.5-1.el7.x86_64.rpm
wget https://repo.mongodb.org/yum/redhat/7/mongodb-org/4.0/x86_64/RPMS/mongodb-org-shell-4.0.5-1.el7.x86_64.rpm

for i in $(ls); do echo "|Installing ==== $i ====|"; rpm -ivh $i ; done

sudo service mongod start
```

### 3) Install Redis

In order to compile Redis from source, you have to run the following commands:

__*The following operations have to be done as root*__

```bash
mkdir /opt/Redis
cd $_
wget http://download.redis.io/releases/redis-5.0.3.tar.gz
tar xf redis-5.0.3.tar.gz
cd redis-5.0.3.tar.gz
make
make install
```

__*AUTOMATED CONFIGURATION*__:

Redis came with an usefull script for automatize the install the server.
If you want to use the default configuration provided, use the following command:

```bash
cd utils
bash install_server.sh
```

Now you have to press enter for confirm the default configuration location.

#### Post Prerequisites

__*NOTE*__:

- *It's preferable to logout and login to the system for a fresh reload of the configuration after have installed all the packaged listed below.*

## Installing

The dependendencies used by the tool can be downloaded as following:
NOTE:

```bash
  go get -v -u github.com/valyala/fasthttp
  go get -v -u github.com/sirupsen/logrus
  go get -v -u github.com/onrik/logrus/filename
  go get -v -u github.com/go-redis/redis
  go get -v -u github.com/globalsign/mgo
  

  go get -v -u github.ibm.com/Alessio-Savi/AuthentiGo # Download the code
```

In case of problem, you have to download it manually

```bash
  cd $GOPATH/src
  git clone --recursive git@github.ibm.com:Alessio-Savi/AuthentiGo.git
  git clone --recursive git@github.ibm.com:Alessio-Savi/AuthentiGo.git
  cd AuthentiGo
  go build
```

## Running the tests

Unfortunatly no test are provided with the initial versione of the software :/

## Deployment

You can deploy the application in two methods:

- Deploy the executable in your remote machine
  - Build the source in your local machine
  - Deploy the executable
- Copy the code to you remote machine, run the following commands

```bash
scp -r authentigo.go auth/ user@machine.preprodiction.log:/home/no_sudo_user/AuthentiGo #Copy the code into your user folder
ssh user@machine.preprodiction.log # Log in into the machine
cd /home/no_sudo_user/AuthentiGo
```

Now that you have a fresh version of the code and you are in the directory of the sources file

```bash
exe="authentigo" # Name of the executable generated
code="authentigo.go" # Name of the main source code

echo "Killing the process ..."
pkill $exe # Killing all process that are named like $exe value
echo "Deleting old code ..."
truncate -s0 $code # Empty the file containing the old code
echo "Copy your code"
vi $code # Paste the code here
echo "Cleaning old compilation files ..."
go clean # Remove build executable
echo "Copy the new utilies sources files ..."
cp -r $code auth/ $GOPATH/src/authentigo # Copy the code into the $GOPATH
echo "Building new executables ... "
go build $code
echo "Stripping debug symbols"
strip -s $exe
mkdir logs # create a folder for the logs
nohup ./$exe -path utils -port 8080 > logs/logs.txt & # Just run in background
```

## Built With

- [FastHTTP](https://github.com/valyala/fasthttp) - HTTP Framework | Tuned for high performance. Zero memory allocations in hot paths. Up to 10x faster than net/http
- [logrus](https://github.com/Sirupsen/logrus) - Pretty logging framework | Not the fastest but very cool and customizable
  - [filename](https://github.com/onrik/logrus/filename) - Plugin for logrus | Used fo print the filename and the logline at each entries of the log
- [redis](https://github.com/go-redis/redis) - Useful framework for talk with Redis DB
- [mgo](https://github.com/globalsign/mgo) - The MongoDB driver for Go

## Contributing

- Feel free to open issue in order to __*require new functionality*__
- Feel free to open issue __*if you discover a bug*__
- New idea/request/concept are very appreciated!

## Versioning

We use [SemVer](http://semver.org/) for versioning.

## Authors

- **Alessio Savi** - *Initial work & Concept* - [IBM Client Innovation Center [CIC]](https://github.ibm.com/Alessio-Savi)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

This backend tool it's intended to run over a VPN and be served "*proxypassed & secured*" by a webserver like Apache or Nginx, in order to crypt the traffic and provide a good layer of security.

However, few basic security enhancements will be developed just for fun.

__*DO NOT RUN THIS TOOL AS SUDOUSERS - ROOT*__
