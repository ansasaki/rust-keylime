#!/bin/bash

# Agent port
firewall-cmd --add-port 9002/tcp

# Revocation notification port
firewall-cmd --add-port 8992/tcp
