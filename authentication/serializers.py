from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import User


class RegistrationSerializer(serializers.Serializer):
    """
    Creates a new user.
    Email, username, and password are required.
    Returns a JSON web token.
    """

    # The password must be validated and should not be read by the client
    password = serializers.CharField(min_length=8,
                                     max_length=128,
                                     write_only=True)

    # The client should not be able to send a token along with a registration
    # request. Making `token` read-only handles that for us.
    token = serializers.CharField(read_only=True)

    # The unique validator enforces the unique constraint on our user model.
    username = serializers.CharField(
        min_length=6,
        max_length=25,
        write_only=True,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message='This username is already associated with an account.')
        ])
    email = serializers.EmailField(
        max_length=128,
        write_only=True,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message='This email is already associated with an account.')
        ])

    def validate(self, data):
        password = data.get('password', None)
        if password is not None:
            validate_password(password)
        else:
            raise serializers.ValidationError('A password is required.')
        return data

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    """
    Authenticates an existing user.
    username and password are required.
    Returns a JSON web token.
    """
    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    token = serializers.CharField(read_only=True)

    def validate(self, data):
        """
        Validates user data.
        """
        email = data.get('email', None)
        password = data.get('password', None)

        if email is None:
            raise serializers.ValidationError(
                'An email address is required to log in.')

        if password is None:
            raise serializers.ValidationError(
                'A password is required to log in.')

        user = authenticate(username=email, password=password)

        if user is None:
            raise serializers.ValidationError(
                'A user with this email and password was not found.')

        if not user.is_active:
            raise serializers.ValidationError(
                'This user has been deactivated.')

        data['token'] = user.token

        return data
