from django.urls import path
from . import views

urlpatterns = [
    path('api/notes/', views.create_note),
    path('api/export/', views.export_users),
    path('api/notes/<int:pk>/delete/', views.delete_note),
    path('api/admin/role/', views.set_role),
    path('login/', views.login_view),
    path('webhooks/pay/', views.pay_hook),
    path('api/import/', views.import_url),
    path('api/upload/', views.upload),
    path('api/items/', views.items),
]
