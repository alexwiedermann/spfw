FROM centos:latest
RUN yum install -y epel-release
RUN yum install -y python python2-pip
ADD ip.py /ip.py
ADD requeriments.txt /requeriments.txt
RUN pip install -r requeriments.txt
ENTRYPOINT ["python"]
CMD ["ip.py"]
