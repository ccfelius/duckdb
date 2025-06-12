import pytest
import subprocess
import sys
from typing import List
from conftest import ShellTest
import os

# the correct keys used are:
# 'masterkey' for created_with_master_key.db
# 'userkey' for created_with_user_key.db
# 'attachkey' for created_with_attach.db


def test_no_key(shell):
    """
    Encrypted database created withouth a -key or -master_key
    throws an error
    """

    test = ShellTest(shell, arguments=['test/storage/encryption/created_with_master_key.db'])

    result = test.run()
    result.check_stderr(
        'Error: unable to open database "test/storage/encryption/created_with_master_key.db": Catalog Error: Cannot open encrypted database "test/storage/encryption/created_with_master_key.db" without a key'
    )


def test_correct_master_key(shell):
    """
    Encrypted database created with -master_key in the command line
    Opened with 'created_with_user_key.db' -master_key masterkey
    """

    test = (
        ShellTest(shell, arguments=['-master_key', 'masterkey'])
        .statement("ATTACH 'test/storage/encryption/created_with_master_key.db' as enc")
        .statement("USE enc")
        .statement("select l_orderkey from lineitem limit 1;")
    )

    result = test.run()
    result.check_stdout('1')


def test_wrong_master_key(shell):
    """
    Encrypted database created with -master_key in the command line
    Opened with 'created_with_user_key.db' -master_key masterkey
    Incorrect master key is given as input
    """

    test = ShellTest(shell, arguments=['-master_key', 'xxx']).statement(
        "ATTACH 'test/storage/encryption/created_with_master_key.db' as enc"
    )

    result = test.run()
    result.check_stderr(
        'IO Error: Master key found in cache, but wrong encryption key used to open the database file.\nTry to explicitly define an ENCRYPTION_KEY with ATTACH'
    )


def test_correct_user_key(shell):
    """
    Encrypted database created with -key in the command line
    Opened with 'created_with_user_key.db' -key userkey
    """
    test = ShellTest(
        shell, arguments=['test/storage/encryption/created_with_user_key.db', '-key', 'userkey']
    ).statement("select l_orderkey from lineitem limit 1;")

    result = test.run()
    result.check_stdout('1')


def test_wrong_user_key(shell):
    """
    Encrypted database created with -key in the command line
    Opened with 'created_with_user_key.db' -key
    """

    test = ShellTest(shell, arguments=['test/storage/encryption/created_with_user_key.db', '-key', 'xxx'])

    result = test.run()
    result.check_stderr('IO Error: Wrong encryption key used to open the database file')


def test_correct_user_key_attach(shell):
    """
    Encrypted database created with attach
    Opened with 'created_with_attach.db' -key
    """

    test = ShellTest(
        shell, arguments=['test/storage/encryption/created_with_attach.db', '-key', 'attachkey']
    ).statement("select l_orderkey from lineitem limit 1;")

    result = test.run()
    result.check_stdout('1')


def test_wrong_user_key_attach(shell):
    """
    Encrypted database created with attach
    Opened with 'created_with_attach.db' -key
    """

    test = ShellTest(shell, arguments=['test/storage/encryption/created_with_attach.db', '-key', 'xxx'])

    result = test.run()
    result.check_stderr('IO Error: Wrong encryption key used to open the database file')


def test_wrong_master_key_no_explicit_attach_key(shell):
    """
    Encrypted database created with attach
    -master_key given as input, but this key differs from the encryption key
    so it throws an error
    """

    test = ShellTest(shell, arguments=['-master_key', 'masterkey']).statement(
        "ATTACH 'test/storage/encryption/created_with_attach.db' as enc"
    )

    result = test.run()
    result.check_stderr(
        'IO Error: Master key found in cache, but wrong encryption key used to open the database file.\nTry to explicitly define an ENCRYPTION_KEY with ATTACH'
    )


def test_wrong_master_key_correct_attach(shell):
    """
    Encrypted database created with attach
    Opened with 'created_with_attach.db' -master_key
    but explicitly uses another key on attach
    """

    test = (
        ShellTest(shell, arguments=['-master_key', 'masterkey'])
        .statement("ATTACH 'test/storage/encryption/created_with_attach.db' as enc (ENCRYPTION_KEY attachkey)")
        .statement("USE enc")
        .statement("select l_orderkey from lineitem limit 1;")
    )

    result = test.run()
    result.check_stdout('1')


def test_explicit_user_key_and_master_key(shell):
    """
    Encrypted database created with user_key
    Opened with 'created_with_user_key.db' -master_key masterkey -user_key userkey
    """

    test = ShellTest(
        shell,
        arguments=['-master_key', 'masterkey', '-key', 'userkey', 'test/storage/encryption/created_with_user_key.db'],
    ).statement("select l_orderkey from lineitem limit 1;")

    result = test.run()
    result.check_stderr(
        'Cannot specify both -key and -master_key.\nError: unable to open database "test/storage/encryption/created_with_user_key.db'
    )


def test_user_key_no_database(shell):
    """
    Opened with -key userkey
    but no database is found as input
    """

    test = ShellTest(shell, arguments=['-key', 'userkey'])

    result = test.run()
    result.check_stderr('Error: key specified but no database found')


# Long test key: test_key_U2FsdGVkX18+0aLSpbJ9V0hVTVV1oYlJbVhGZ0NMTkpqaWp4R3hNR2VaUkVHaVRqR1htR3V1QXZmc0NtbUxSaUlwWVdoVkNrT0RUR2pqUGxkUVdtSmtOUldHWlJRa05JUWlVSkZaVk10aEZXR2FRa0Z6eEx0VlZIVG9LR0UwRkdNZ0xXaEpKWkNKRW5BaXlLSnNWTkdWTkpHZ0ZR
#


def test_long_base64_user_key(shell):
    """
    Opened with a long -key
    """

    test = ShellTest(
        shell,
        arguments=[
            'test/storage/encryption/base64_encrypted.db',
            '-key',
            'test_key_U2FsdGVkX18+0aLSpbJ9V0hVTVV1oYlJbVhGZ0NMTkpqaWp4R3hNR2VaUkVHaVRqR1htR3V1QXZmc0NtbUxSaUlwWVdoVkNrT0RUR2pqUGxkUVdtSmtOUldHWlJRa05JUWlVSkZaVk10aEZXR2FRa0Z6eEx0VlZIVG9LR0UwRkdNZ0xXaEpKWkNKRW5BaXlLSnNWTkdWTkpHZ0ZR',
        ],
    ).statement("select l_orderkey from lineitem limit 1;")

    result = test.run()
    result.check_stdout('1')


def test_long_base64_master_key(shell):
    """
    Opened with a long -master_key
    """

    test = (
        ShellTest(
            shell,
            arguments=[
                '-master_key',
                'test_key_U2FsdGVkX18+0aLSpbJ9V0hVTVV1oYlJbVhGZ0NMTkpqaWp4R3hNR2VaUkVHaVRqR1htR3V1QXZmc0NtbUxSaUlwWVdoVkNrT0RUR2pqUGxkUVdtSmtOUldHWlJRa05JUWlVSkZaVk10aEZXR2FRa0Z6eEx0VlZIVG9LR0UwRkdNZ0xXaEpKWkNKRW5BaXlLSnNWTkdWTkpHZ0ZR',
            ],
        )
        .statement("ATTACH 'test/storage/encryption/base64_encrypted.db' as enc")
        .statement("USE enc")
        .statement("select l_orderkey from lineitem limit 1;")
    )

    result = test.run()
    result.check_stdout('1')
