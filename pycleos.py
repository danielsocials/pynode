#!/usr/bin/env python3
import config
from pyeos.node import *
import time
import datetime
import json
from pytest import fixture
import hashlib
import asyncore
import logging
import threading
from pyeos.rpc import RpcClient
import click

@click.group()
def cli():
    "Python Command Line Interface to EOS/ENU Client"

@cli.group()
@click.pass_context
def get(ctx):
    #click.echo('Get information from the blockchain')
    pass

#@get.group('info')
@get.command()
def get_info():
    click.echo('The subcommand')
    client = RpcClient(username=config.rpcuser, password=config.rpcpass)
    info = client.get_info()
    print(info)

@get.group('block')
@click.argument('block_num')
def get_block():
    pass

@get.group('transaction')
@click.argument('txid')
def get_transaction():
    pass

@cli.group()
@click.pass_context
def net(ctx):
    pass
 
@cli.group()
@click.pass_context
def system(ctx):
    pass
 
@cli.group()
@click.pass_context
def push(ctx):
    click.echo('Get information from the blockchain')

@cli.group()
@click.pass_context
def sign(ctx):
    click.echo('Get information from the blockchain')
 
@cli.group()
@click.pass_context
def version(ctx):
    click.echo('Get information from the blockchain')

@cli.group()
@click.pass_context
def set(ctx):
    print("not support")

@cli.group()
@click.pass_context
def wallet(ctx):
    print("not support")
 
if __name__ == '__main__':
        cli() 
