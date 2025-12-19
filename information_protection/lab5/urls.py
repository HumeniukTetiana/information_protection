from django.urls import path
from . import views

app_name = 'lab5'

urlpatterns = [
    path('', views.digital_signature_tool, name='lab5'),
]
