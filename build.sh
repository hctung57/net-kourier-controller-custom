#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
YELLOW="\e[33m"
NC="\e[0m"

logSuccess() { echo -e "$GREEN-----$message-----$NC";}
logError() { echo -e "$RED-----$message-----$NC";}
logInfo() { echo -e "$BLUE###############---$message---###############$NC";}

clear
export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:/home/master/go/bin
echo -e "${YELLOW}このスクリプトはボナちゃんによって書かれています${NC}";
message="ko build image" && logInfo
export KO_DOCKER_REPO="ko.local"
ko build cmd/kourier/main.go
if [ "$?" -ne "0" ]; then
    message="ko build error" && logError
    exit 1
else
    message="ko build successfully" && logSuccess
fi

echo -e "\n"
message="change image from docker to crictl" && logInfo
image=$(docker images | grep ko.local | grep latest | awk '{print $1}'):latest
docker rmi -f hctung57/kourier:latest
docker image tag $image docker.io/hctung57/kourier:latest
docker rmi $image
docker push hctung57/kourier:latest
image=$(docker images | grep ko.local | awk '{print $1}'):$(docker images | grep ko.local | awk '{print $2}')
docker rmi $image
# docker save -o kourier.tar docker.io/hctung57/kourier:latest
# message="Saved atarashi-imeji to .tar file" && logSuccess
# sudo crictl rmi docker.io/hctung57/kourier:latest
# sudo ctr -n=k8s.io images import kourier.tar
# message="Untar atarashi-imeji" && logSuccess
# rm -rf kourier.tar

echo -e "\n"
message="remove current Pod" && logInfo
pod=$(kubectl -n knative-serving get pod | grep net-kourier | awk '{print $1}')
kubectl -n knative-serving delete pod/$pod

curlStatus=$(curl -I hello.default | head -n 1| cut -d $' ' -f2)
echo $curlStatus
if [ $curlStatus -eq "200" ]; then
    message="curl success" && logSuccess
    pod=$(kubectl -n knative-serving get pod | grep net-kourier | awk '{print $1}')
    kubectl -n knative-serving wait --for=condition=ready pod $pod > /dev/null 2>&1
    clear
    message="net-kourier logs" && logInfo
    kubectl -n knative-serving logs $pod -f
else
    message="curl failed" && logError
    exit 2
fi
