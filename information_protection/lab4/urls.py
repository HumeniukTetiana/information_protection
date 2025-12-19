from django.urls import path
from . import views

app_name = 'lab4'

urlpatterns = [
    path('', views.lab4, name='lab4_rsa'),
]
