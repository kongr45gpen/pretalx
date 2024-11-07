from contextlib import suppress

from django.contrib.auth import authenticate, login
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import MultipleObjectsReturned

from pretalx.person.models import User


class AuthenticationTokenBackend(ModelBackend):
    def authenticate(self, *args, token=None, **kwargs):
        if token:
            with suppress(User.DoesNotExist, MultipleObjectsReturned):
                return User.objects.get(auth_token__key__iexact=token)
        return None


class AuthenticationTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            token = None
            user = None
            if "Authorization" in request.headers:
                token = request.headers["Authorization"].lower()
                token = token[len("token ") :] if token.startswith("token ") else token
                user = authenticate(
                    request,
                    token=token,
                    backend="pretalx.common.auth.AuthenticationTokenBackend",
                )

                if user:
                    request.user = user
            elif "token" in request.GET:
                token = request.GET["token"]
                #request.GET.pop("token")
                user = authenticate(
                    request,
                    token=token,
                    backend="pretalx.common.auth.AuthenticationTokenBackend",
                )

                if user:
                    login(request, user)
        return self.get_response(request)
