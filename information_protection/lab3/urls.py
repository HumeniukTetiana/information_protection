# lab3/urls.py
from django.urls import path
from . import views

app_name = 'lab3'

urlpatterns = [
    path('', views.lab3_view, name='lab3'),
]
