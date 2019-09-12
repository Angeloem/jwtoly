from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import viewsets
from .serializers import (LoginSerializer, RegistrationSerializer)


class UserViewSet(viewsets.ViewSet):
    """
    The `auth` endpoint allows only specific actions including login, registration, etc.
    """

    @action(detail=False , methods=['post'], permission_classes=[AllowAny])
    def login(self, request):
        """
        Login existing `User`.
        """
        printed = request.data
        print(printed)
        serializer = LoginSerializer(data=printed)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def registration(self, request):
        """
        Register a new `User` account.
        """
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
