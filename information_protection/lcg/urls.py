from django.urls import path
from . import views

urlpatterns = [
    path('', views.generate_lcg, name='lab1'),
]
