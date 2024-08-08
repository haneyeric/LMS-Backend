from importlib import import_module
from re import sub
from django.shortcuts import render
from django.template.loader import render_to_string
# from django.conf import settings
# from django.core.mail import send_mail
from environs import Env

env = Env()
env.read_env()

EMAIL_BACKEND = env('EMAIL_BACKEND')
EMAIL_HOST = env('EMAIL_HOST')
EMAIL_USE_TLS = env('EMAIL_USE_TLS')
EMAIL_PORT = env('EMAIL_PORT')
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')

from api import serializer as api_serializer
from userauths.models import User, Profile

from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import generics, status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
import smtplib

import random

def generate_random_otp(length=6):
    otp = ''.join([str(random.randint(0,9)) for _ in range(length)])
    return otp

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = api_serializer.MyTokenObtainPairSerializer

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = api_serializer.RegistrationSerializer

class PasswordResetEmailVerifyAPIView(generics.RetrieveAPIView):
    permission_classes = [AllowAny]
    serializer_class = api_serializer.UserSerializer

    def get_object(self):
        email = self.kwargs['email']

        user = User.objects.filter(email=email).first()

        if user:
            uuidb64 = user.pk
            refresh = RefreshToken.for_user(user)
            refresh_token = str(refresh.access_token)
            user.refresh_token = refresh_token
            user.otp = generate_random_otp()
            user.save()
            
            link = f"http://localhost:5173/create-new-password/?otp={user.otp}&uuidb64={uuidb64}&refresh_token={refresh_token}"
            
            context = {
                "link": link,
                "username": user.username,
            }
            
            
            
            subject = 'Password Reset Email'
            email_from = EMAIL_HOST_USER
            recipient_list = [user.email]
            # text_body = render_to_string("email/password_reset.txt", context)
            html_body = render_to_string("email/password_reset.html", context)
            connection = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
            connection.starttls()
            connection.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
            connection.sendmail(
                from_addr=EMAIL_HOST,
                to_addrs=user.email,
                msg=html_body
            )
            connection.close()

            # send_mail(subject, html_body, email_from, recipient_list)
        
        return user
    
class PasswordChangeAPIView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = api_serializer.UserSerializer

    def create(self, request, *args, **kwargs):
        payload = request.data

        otp = payload['otp']
        uuidb64 = payload['uuidb64']
        password = payload['password']

        user = User.objects.get(id=uuidb64, otp=otp)
        if user:
            user.set_password(password)
            user.otp = ""
            user.save()

            return Response({"message": "Password Change Successfully"}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message": "User Does Not Exist"}, status=status.HTTP_404_NOT_FOUND)