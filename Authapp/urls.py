from django.urls import path
from . import views
urlpatterns = [
    path('AccessToken2API/',views.AccessToken2API.as_view(), name = "AccessToken2API"),
    path('decrypt/',views.decrypt, name = "decrypt"),
    path("logout/", views.logout, name = "logout")
]
