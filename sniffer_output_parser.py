#!/bin/python3

with open("log.txt", "r") as fp:
    context = fp.read()
    context_split = context.split(",")

    c_all = []
    for c in context_split:
        if len(c.strip()) > 0:
            c_all.append(int(c))

    s_all = []
    for i in range(22, 65535):
        s_all.append(i)

    missing_port = []
    for s in s_all:
        if s not in c_all:
            missing_port.append(s)

    print("missing_port len: {}".format(len(missing_port)))
    print("missing_port: {}".format(missing_port))
