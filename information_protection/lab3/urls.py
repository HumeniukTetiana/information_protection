# lab3/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.lab3_view, name='lab3'),
]
