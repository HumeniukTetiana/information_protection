from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('lab1/', include('lcg.urls')),
    path('lab2/', include('lab2.urls')),
    # path('lab3/', include('lab3.urls')),
    # path('lab4/', include('lab4.urls')),
    # path('lab5/', include('lab5.urls')),
]

