from django.urls import path
from . import views

urlpatterns = [
    path('', views.main_hash, name='lab2'),
    path('download/', views.download_md5, name='download_md5'),
]
