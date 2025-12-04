from django.urls import path
from . import views

urlpatterns = [
    path('', views.lab4, name='lab4_rsa'),
]
