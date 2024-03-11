from django.contrib import admin
from .models import Account
# Register your models here.

class AccountAdmin(admin.ModelAdmin):
    model = Account
    list_display = ['username', 'password']

admin.site.register(Account, AccountAdmin)