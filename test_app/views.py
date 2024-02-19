from rest_framework import permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from ansible_base.lib.utils.views.ansible_base import AnsibleBaseView
from ansible_base.rbac.api.permissions import AnsibleBaseObjectPermissions
from test_app import serializers
from test_app.models import RelatedFieldsTestModel, User


class TestAppViewSet(ModelViewSet, AnsibleBaseView):
    permission_classes = [AnsibleBaseObjectPermissions]

    def get_queryset(self):
        return self.serializer_class.Meta.model.access_qs(self.request.user)


class OrganizationViewSet(TestAppViewSet):
    serializer_class = serializers.OrganizationSerializer


class TeamViewSet(TestAppViewSet):
    serializer_class = serializers.TeamSerializer


class UserViewSet(ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.UserSerializer

    def get_queryset(self):
        return User.objects.all()


class EncryptionModelViewSet(TestAppViewSet):
    serializer_class = serializers.EncryptionModelSerializer


class RelatedFieldsTestModelViewSet(TestAppViewSet):
    queryset = RelatedFieldsTestModel.objects.all()  # needed for automatic basename from router
    serializer_class = serializers.RelatedFieldsTestModelSerializer


class EncryptedModelViewSet(TestAppViewSet):
    serializer_class = serializers.EncryptionModelSerializer


class InventoryViewSet(TestAppViewSet):
    serializer_class = serializers.InventorySerializer


class CowViewSet(TestAppViewSet):
    serializer_class = serializers.CowSerializer
    rbac_action = None

    @action(detail=True, rbac_action='say', methods=['post'])
    def cowsay(self, request, pk=None):
        self.get_object()  # this triggers the permission check
        return Response({'detail': 'moooooo'})


class UUIDModelViewSet(TestAppViewSet):
    serializer_class = serializers.UUIDModelSerializer
