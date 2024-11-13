from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from django.conf.urls.static import static
from django.conf import settings
from djangoapp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('djangoapp/', include('djangoapp.urls')),
    
    # Static pages
    path('', TemplateView.as_view(template_name="Home.html"), name='home'),
    path('about/', TemplateView.as_view(template_name="About.html"), name='about'),
    path('contact/', TemplateView.as_view(template_name="Contact.html"), name='contact'),
    
    # Dynamic routes for authentication and dealers
    path('login/', views.login_user, name='login'),
    path('register/', views.registration, name='register'),
    path('dealers/', views.get_dealers, name='dealers'),
    path('dealer/<int:dealer_id>/', views.get_dealer_details, name='dealer_details'),
    
    # Review submission
    path('postreview/<int:dealer_id>/', views.add_review, name='post_review'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
