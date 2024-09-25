from django.urls import path
from . import views
urlpatterns = [
    path('adminLoginAPI/', views.adminLoginAPI.as_view() , name='adminLoginAPI'),
    path('scanUrlAPI/', views.scanUrlAPI.as_view() , name='scanUrlAPI'),
    path('filescanAPI/', views.filescanAPI.as_view() , name='filescanAPI'),
    path('demofilescanAPI/', views.demofilescanAPI.as_view() , name='demofilescanAPI'),
]