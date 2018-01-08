FROM centos:latest
RUN yum install -y epel-release
RUN yum install -y python python2-pip
RUN pip install flask
ADD ip.py /ip.py
ENTRYPOINT ["python"]
CMD ["ip.py"]
