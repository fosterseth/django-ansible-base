import datetime
import os
import re
from collections import defaultdict
from unittest import mock

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.apps import apps
from django.db.migrations.recorder import MigrationRecorder
from django.db.models.signals import post_migrate
from django.test.client import RequestFactory

from ansible_base.lib.testing.fixtures import *  # noqa: F403, F401
from ansible_base.lib.testing.util import copy_fixture
from test_app import models


def test_migrations_okay(*args, **kwargs):
    """This test is not about the code, but for verifying your own state.

    If you are not migrated to the correct state, this may hopefully alert you.
    This is targeted toward situations like switching branches.
    """
    disk_steps = defaultdict(set)
    app_exceptions = {'default': 'auth', 'social_auth': 'social_django'}
    for app in MigrationRecorder.Migration.objects.values_list('app', flat=True).distinct():
        if app in app_exceptions:
            continue
        app_config = apps.get_app_config(app)
        for path in os.listdir(os.path.join(app_config.path, 'migrations')):
            if re.match(r'^\d{4}_.*.py$', path):
                disk_steps[app].add(path.rsplit('.')[0])
    db_steps = defaultdict(set)
    for record in MigrationRecorder.Migration.objects.only('app', 'name'):
        if record.app in app_exceptions:
            continue
        app_name = app_exceptions.get(record.app, record.app)
        db_steps[app_name].add(record.name)
    for app in disk_steps:
        assert disk_steps[app] == db_steps[app], f'Migrations not expected for app {app}, perhaps you need --create-db?'


post_migrate.connect(test_migrations_okay)


@pytest.fixture
def github_configuration():
    return {
        "CALLBACK_URL": "https://localhost/api/gateway/callback/github_test/",
        "KEY": "12345",
        "SECRET": "abcdefg12345",
    }


@pytest.fixture
def github_organization_configuration():
    return {
        "CALLBACK_URL": "https://localhost/api/gateway/callback/github_org_test/",
        "KEY": "12345",
        "SECRET": "abcdefg12345",
        "NAME": "foo-org",
    }


@pytest.fixture
def github_team_configuration():
    return {
        "CALLBACK_URL": "https://localhost/api/gateway/callback/github_team_test/",
        "KEY": "12345",
        "SECRET": "abcdefg12345",
        "ID": "foo-team",
    }


@pytest.fixture
def github_enterprise_configuration():
    return {
        "CALLBACK_URL": "https://localhost/api/gateway/callback/github_enterprise_test/",
        "KEY": "12345",
        "SECRET": "abcdefg12345",
        "URL": "https://foohub.com",
        "API_URL": "https://api.foohub.com",
    }


@pytest.fixture
def github_enterprise_organization_configuration():
    return {
        "CALLBACK_URL": "https://localhost/api/gateway/callback/github_enterprise_organization_test/",
        "KEY": "12345",
        "SECRET": "abcdefg12345",
        "URL": "https://foohub.com",
        "API_URL": "https://api.foohub.com",
        "NAME": "foo-org",
    }


@pytest.fixture
def github_enterprise_team_configuration():
    return {
        "CALLBACK_URL": "https://localhost/api/gateway/callback/github_enterprise_team_test/",
        "KEY": "12345",
        "SECRET": "abcdefg12345",
        "URL": "https://foohub.com",
        "API_URL": "https://api.foohub.com",
        "ID": "foo-team",
    }


@pytest.fixture
def github_authenticator(github_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test Github Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.github",
        configuration=github_configuration,
    )
    return authenticator


@pytest.fixture
def github_organization_authenticator(github_organization_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test Github Organization Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.github_org",
        configuration=github_organization_configuration,
    )
    return authenticator


@pytest.fixture
def github_team_authenticator(github_team_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test Github Organization Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.github_team",
        configuration=github_team_configuration,
    )
    return authenticator


@pytest.fixture
def github_enterprise_authenticator(github_enterprise_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test Github Enterprise Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.github_enterprise",
        configuration=github_enterprise_configuration,
    )
    return authenticator


@pytest.fixture
def github_enterprise_organization_authenticator(github_enterprise_organization_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test Github Enterprise Organization Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.github_enterprise_org",
        configuration=github_enterprise_organization_configuration,
    )
    return authenticator


@pytest.fixture
def github_enterprise_team_authenticator(github_enterprise_team_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test Github Enterprise Team Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.github_enterprise_team",
        configuration=github_enterprise_team_configuration,
    )
    return authenticator


@pytest.fixture
def oidc_configuration():
    return {
        "OIDC_ENDPOINT": "https://localhost/api/gateway/callback/oidc_test/",
        "OIDC_VERIFY_SSL": True,
        "KEY": "12345",
        "SECRET": "abcdefg12345",
    }


@pytest.fixture
def oidc_authenticator(oidc_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test OIDC Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.oidc",
        configuration=oidc_configuration,
    )
    yield authenticator
    authenticator.authenticator_user.all().delete()
    authenticator.delete()


@pytest.fixture
def ldap_configuration():
    return {
        "SERVER_URI": ["ldap://ldap06.example.com:389"],
        "BIND_DN": "cn=ldapadmin,dc=example,dc=org",
        "BIND_PASSWORD": "securepassword",
        "START_TLS": False,
        "CONNECTION_OPTIONS": {"OPT_REFERRALS": 0, "OPT_NETWORK_TIMEOUT": 30},
        "USER_SEARCH": ["ou=users,dc=example,dc=org", "SCOPE_SUBTREE", "(cn=%(user)s)"],
        "USER_DN_TEMPLATE": "cn=%(user)s,ou=users,dc=example,dc=org",
        "USER_ATTR_MAP": {"email": "mail", "last_name": "sn", "first_name": "givenName"},
        "GROUP_SEARCH": ["ou=groups,dc=example,dc=org", "SCOPE_SUBTREE", "(objectClass=groupOfNames)"],
        "GROUP_TYPE": "MemberDNGroupType",
        "GROUP_TYPE_PARAMS": {"name_attr": "cn", "member_attr": "member"},
    }


@pytest.fixture
def ldap_authenticator(ldap_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test LDAP Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.ldap",
        configuration=ldap_configuration,
    )
    return authenticator


@pytest.fixture
def tacacs_configuration():
    return {
        "PORT": 49,
        "HOST": "localhost",
        "AUTH_PROTOCOL": "ascii",
        "REM_ADDR": True,
        "SECRET": "ciscotacacskey",
        "SESSION_TIMEOUT": 5,
    }


@pytest.fixture
def tacacs_authenticator(tacacs_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test TACACS Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.tacacs",
        configuration=tacacs_configuration,
    )
    yield authenticator
    authenticator.authenticator_user.all().delete()
    authenticator.delete()


@pytest.fixture
def saml_configuration(rsa_keypair_with_cert, rsa_keypair_with_cert_1):
    return {
        "CALLBACK_URL": "https://localhost/api/social/complete/ansible_base-authenticator_plugins-saml__test-saml-authenticator/",
        "SP_ENTITY_ID": "saml_entity",
        "SP_PUBLIC_CERT": rsa_keypair_with_cert.certificate,
        "SP_PRIVATE_KEY": rsa_keypair_with_cert.private,
        "ORG_INFO": {"en-US": {"url": "http://localhost", "name": "test app", "displayname": "Test App"}},
        "TECHNICAL_CONTACT": {'givenName': "Technical Doe", 'emailAddress': "tdoe@example.com"},
        "SUPPORT_CONTACT": {'givenName': "Support Doe", 'emailAddress': "sdoe@example.com"},
        "SP_EXTRA": {"requestedAuthnContext": False},
        "SECURITY_CONFIG": {},
        "EXTRA_DATA": [],
        "IDP_URL": "https://idp.example.com/idp/profile/SAML2/Redirect/SSO",
        "IDP_X509_CERT": rsa_keypair_with_cert_1.certificate,
        "IDP_ENTITY_ID": "https://idp.example.com/idp/shibboleth",
        "IDP_GROUPS": "groups",
        "IDP_ATTR_EMAIL": "email",
        "IDP_ATTR_USERNAME": "username",
        "IDP_ATTR_LAST_NAME": "last_name",
        "IDP_ATTR_FIRST_NAME": "first_name",
        "IDP_ATTR_USER_PERMANENT_ID": "user_permanent_id",
    }


@pytest.fixture
def saml_authenticator(saml_configuration):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test SAML Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.saml",
        configuration=saml_configuration,
    )
    return authenticator


@pytest.fixture
def custom_authenticator(db):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test Custom Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="test_app.tests.fixtures.authenticator_plugins.custom",
        configuration={},
    )
    return authenticator


@pytest.fixture
def keycloak_authenticator(db):
    from ansible_base.authentication.models import Authenticator

    authenticator = Authenticator.objects.create(
        name="Test Keycloak Authenticator",
        enabled=True,
        create_objects=True,
        users_unique=False,
        remove_users=True,
        type="ansible_base.authentication.authenticator_plugins.keycloak",
        configuration={
            "ACCESS_TOKEN_URL": "asdf",
            "AUTHORIZATION_URL": "asdf",
            "KEY": "asdf",
            "PUBLIC_KEY": "asdf",
            "SECRET": "asdf",
        },
    )
    return authenticator


@copy_fixture(copies=3)  # noqa: F405
@pytest.fixture
def local_authenticator_map(db, local_authenticator, user, randname):
    from ansible_base.authentication.models import AuthenticatorMap

    authenticator_map = AuthenticatorMap.objects.create(
        name=randname("Test Local Authenticator Map"),
        authenticator=local_authenticator,
        map_type="is_superuser",
        triggers={"always": {}},
        organization="testorg",
        team="testteam",
    )
    return authenticator_map


# Generate public and private keys for testing
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())


@pytest.fixture
def test_encryption_private_key():
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def test_encryption_public_key():
    return (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


@pytest.fixture
def jwt_token(test_encryption_private_key):
    class Token:
        def __init__(self):
            expiration_date = datetime.datetime.now() + datetime.timedelta(minutes=10)
            self.unencrypted_token = {
                "iss": "ansible-issuer",
                "exp": int(expiration_date.timestamp()),
                "aud": "ansible-services",
                "sub": "john.westcott.iv",
                "first_name": "john",
                "last_name": "westcott",
                "email": "noone@redhat.com",
                "is_superuser": False,
                "is_system_auditor": False,
                "claims": {"organizations": {}, "teams": {}},
            }

        def encrypt_token(self):
            return jwt.encode(self.unencrypted_token, test_encryption_private_key, algorithm="RS256")

    test_token = Token()
    return test_token


@pytest.fixture
def mocked_http(test_encryption_public_key, jwt_token):
    class MockedHttp:
        def mocked_get_decryption_key_get_request(self, *args, **kwargs):
            class MockResponse:
                def __init__(self, text, status_code):
                    self.status_code = 200
                    self.text = text
                    self.status_code = status_code

            if args[0] == 'http://someotherurl.com/200_junk/api/gateway/v1/jwt_key/':
                return MockResponse("Junk", 200)
            elif args[0] == 'http://someotherurl.com/200_good/api/gateway/v1/jwt_key/':
                return MockResponse(test_encryption_public_key, 200)
            elif args[0] == 'http://someotherurl.com/302/api/gateway/v1/jwt_key/':
                return MockResponse(None, 302)
            elif args[0] == 'http://someotherurl.com/504/api/gateway/v1/jwt_key/':
                return MockResponse(None, 504)

            return MockResponse(None, 404)

        def mocked_parse_jwt_token_get_request(self, *args, **kwargs):
            rf = RequestFactory()
            get_request = rf.get('/hello/')
            if args[0] == 'with_headers':
                get_request.headers = {'X-DAB-JW-TOKEN': jwt_token.encrypt_token()}
            return get_request

        def mocked_gateway_view_get_request(self, *args, **kwargs):
            # First argument is whether or not the user should be authenticated
            rf = RequestFactory()
            get_request = rf.get('/hello/')

            mocked_user = mock.Mock(is_authenticated=args[0])
            get_request.user = mocked_user
            get_request.session = {}
            return get_request

    return MockedHttp()


@pytest.fixture
def system_user(db, settings, no_log_messages):
    with no_log_messages():
        user_obj, _created = models.User.objects.get_or_create(username=settings.SYSTEM_USERNAME)
    yield user_obj


@copy_fixture(copies=3)
@pytest.fixture
def organization(db, randname):
    return models.Organization.objects.create(name=randname("Test Organization"))


@pytest.fixture
def team(organization):
    return models.Team.objects.create(name='foo-team', organization=organization)
