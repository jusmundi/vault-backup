#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Backup/create encrypted/not encrypted dumps from HashiCorps's Vault secrets to json/yaml dumps
# Populate Vault from json/yaml dump
#
# ENV variables:
# VAULT_ADDR: for example: 'http://vault.vault.svc.cluster.local:8200' for k8s cluster
# ROLE_ID: RoleID for AppRole auth
# SECRET_ID: SecretID for AppRole auth
# VAULT_PREFIX: for example 'jenkins'
# DUMP_ENCRYPTION_PASSWORD: password which will be used for secrets dump encryption
#
# Copyright (c) 2021 Igor Zhivilo <igor.zhivilo@gmail.com>
# Licensed under the MIT License
import json
import logging
import os
import sys

import click
import hvac
from colorama import init
from cryptography.fernet import Fernet
from termcolor import colored

# use Colorama to make Termcolor work on Windows too
init()

VAULT_ADDR = os.environ.get('VAULT_ADDR')
ROLE_ID = os.environ.get('ROLE_ID')
SECRET_ID = os.environ.get('SECRET_ID')
VAULT_PREFIX = os.environ.get('VAULT_PREFIX')
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
# DEBUG = os.environ.get('DEBUG')


class VaultHandler:
    def __init__(self, url, role_id, secret_id, path, enc_key, debug, encrypt):
        self.url = url
        self.role_id = role_id
        self.secret_id = secret_id
        self.path = path
        self.enc_key = enc_key
        self.debug = debug
        self.encrypt = encrypt
        self.client = hvac.Client(url=self.url)

        self.client.auth.approle.login(
            role_id=self.role_id,
            secret_id=self.secret_id,
        )

        if not self.client.is_authenticated():
            raise Exception('Vault authentication error!')

    def get_secrets_list(self):
        secrets_list_response = self.client.secrets.kv.v2.list_secrets(
            path='{}'.format(self.path),
        )
        return secrets_list_response['data']['keys']

    def print_all_secrets_with_metadata(self):
        for key in self.get_secrets_list():
            print('\nKey is: {}'.format(key))
            secret_response = self.get_secret(key)
            print(secret_response)

    def _secrets_to_dict(self):
        secrets_dict = {}
        for key in self.get_secrets_list():
            secret_response = self.get_secret(key)

            secret_data = {}
            for k in secret_response['data']['data'].keys():
                secret_data = secret_response['data']['data'].copy()

            secrets_dict[key] = secret_data
        return secrets_dict

    def get_secret(self, key):
        return self.client.secrets.kv.v2.read_secret(
            path='{}/{}'.format(self.path, key),
        )

    def print_secrets_nicely(self, secrets_dict={}):
        if not secrets_dict:
            secrets_dict = self._secrets_to_dict()
        for secret_name, secret in secrets_dict.items():
            print('\n{}'.format(secret_name))
            for attr_name, attr in secret.items():
                print(attr_name, ':', attr)

    def dump_all_secrets(self, dump_path):
        secrets_dict = self._secrets_to_dict()
        self._encrypt_dump(secrets_dict, dump_path)

    def _encrypt_dump(self, secrets_dict, dump_path):
        secrets_dict_byte = json.dumps(secrets_dict).encode('utf-8')
        if self.encrypt:
            f = Fernet(self.enc_key)
            encrypted_data = f.encrypt(secrets_dict_byte)
        else:
            encrypted_data = secrets_dict_byte
        with open(dump_path, 'wb') as file:
            file.write(encrypted_data)

    def _decrypt_dump(self, path_to_dump):
        with open(path_to_dump, 'rb') as file:
            file_data = file.read()
        if self.encrypt:
            f = Fernet(self.enc_key)
            decrypted_data = f.decrypt(file_data).decode('utf-8')
        else:
            decrypted_data = file_data
        return json.loads(decrypted_data)

    def print_secrets_from_encrypted_dump(self, path_to_dump):
        decrypted_data = self._decrypt_dump(path_to_dump)
        self.print_secrets_nicely(decrypted_data)

    def _populate_vault_prefix_from_dict(self, secrets_dict, vault_prefix_to_populate):
        for key in secrets_dict:
            self.client.secrets.kv.v2.create_or_update_secret(
                path='{}/{}'.format(vault_prefix_to_populate, key),
                secret=secrets_dict[key],
            )

    def populate_vault_from_dump(self, vault_prefix_to_populate, path_to_dump):
        secrets_dict = self._decrypt_dump(path_to_dump)
        self._populate_vault_prefix_from_dict(
            secrets_dict, vault_prefix_to_populate,
        )


@click.group(invoke_without_command=True)
@click.option('--debug/--no-debug', default=False)
@click.option('--encrypt/--no-encrypt', default=False, help='Encrypt data')  # noqa: ignore=E501
# @click.option('-e', '--encrypt', is_flag=True, default=True, help='Encrypt data')
@click.pass_context
def cli(ctx, debug=False, encrypt=True):
    group_commands = ['print', 'print-dump', 'dump', 'populate']
    """
    VaultHandler is a command line tool that helps dump/populate secrets of HashiCorp's Vault
    """

    # ensure that ctx.obj exists and is a dict (in case `cli()` is called
    # by means other than the `if` block below)
    ctx.ensure_object(dict)

    ctx.obj['DEBUG'] = debug
    ctx.obj['ENCRYPT'] = encrypt

    if debug:
        logger.setLevel(logging.DEBUG)
        logger.info('Collecting vault data')
        click.echo('Debug mode is %s' % ('on' if debug else 'off'))
        click.echo('Encrypt is %s' % (ctx.obj['ENCRYPT'] and 'on' or 'off'))

    if ctx.invoked_subcommand is None:
        click.echo('Specify one of the commands below')
        print(*group_commands, sep='\n')


@cli.command('print')
@click.option('--debug/--no-debug', default=False)
@click.pass_context
def print_secrets(ctx, debug=False):
    """
    Print secrets nicely.
    """
    if debug:
        logger.info('Printing vault data')

    vault = VaultHandler(
        VAULT_ADDR, ROLE_ID, SECRET_ID,
        VAULT_PREFIX, ENCRYPTION_KEY,
        ctx.obj['DEBUG'], ctx.obj['ENCRYPT'],
    )
    vault.print_secrets_nicely()


@cli.command('print-dump')
@click.pass_context
@click.option('--debug/--no-debug', default=False)
@click.option('--encrypt/--no-encrypt', default=False, help='Encrypt data')  # noqa: ignore=E501
@click.option(
    '--dump_path', '-dp',
    type=str,
    default='vault_secrets.enc',
    help='Path/name of dump with secrets',
)
def print_dump(ctx, dump_path, debug=False, encrypt=True):
    """
    Print secrets from encrypted dump.
    """

    if debug:
        logger.info('Dump data from encrypted dump')
        click.echo(encrypt)

    vault = VaultHandler(
        VAULT_ADDR, ROLE_ID, SECRET_ID,
        VAULT_PREFIX, ENCRYPTION_KEY,
        ctx.obj['DEBUG'], ctx.obj['ENCRYPT'],
    )
    vault.print_secrets_from_encrypted_dump(dump_path)


@cli.command('dump')
@click.pass_context
@click.option('--debug/--no-debug', default=False)
@click.option('--encrypt/--no-encrypt', default=False, help='Encrypt data')  # noqa: ignore=E501
@click.option(
    '--dump_path', '-dp',
    type=str,
    default='vault_secrets.enc',
    help='Path/name of dump with secrets',
)
def dump_secrets(ctx, dump_path, debug=False, encrypt=True):
    """
    Dump secrets from Vault.
    """

    if debug:
        logger.info('Dump vault data')
        click.echo(encrypt)

    vault = VaultHandler(
        VAULT_ADDR, ROLE_ID, SECRET_ID,
        VAULT_PREFIX, ENCRYPTION_KEY,
        ctx.obj['DEBUG'], ctx.obj['ENCRYPT'],
    )
    vault.dump_all_secrets(dump_path)


@cli.command('populate')
@click.pass_context
@click.option('--debug/--no-debug', default=False)
@click.option('--encrypt/--no-encrypt', default=False, help='Encrypt data')  # noqa: ignore=E501
@click.option(
    '--vault_prefix', '-vp',
    type=str,
    required=True,
    help="Vault's prefix to populate from secrets dump",
)
# @click.argument('dump_path', type=click.Path(exists=False))
@click.option(
    '--dump_path', '-dp',
    type=click.Path(exists=False),
    default='vault_secrets.enc',
    help='Path to dump with secrets',
)
def populate_vault_prefix(ctx, vault_prefix, dump_path, debug=False, encrypt=True):
    """
    Populate Vault prefix from dump with secrets.
    """

    if debug:
        logger.info('Populating vault with data')
        click.echo(encrypt)
        # click.echo(click.format_filename(commit_msg_filepath))
        click.echo(vault_prefix)
        click.echo(dump_path)

    vault = VaultHandler(
        VAULT_ADDR, ROLE_ID, SECRET_ID,
        VAULT_PREFIX, ENCRYPTION_KEY,
        ctx.obj['DEBUG'], ctx.obj['ENCRYPT'],
    )
    vault.populate_vault_from_dump(vault_prefix, dump_path)


logger = logging.getLogger('vault')
logger.setLevel(logging.INFO)
stdoutlog = logging.StreamHandler(sys.stdout)
logger.addHandler(stdoutlog)

# pylint:disable=no-value-for-parameter
if __name__ == '__main__':
    cli(obj={})
