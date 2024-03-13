from django.contrib import admin
from .models import Account , Messages
# Register your models here.

class AccountAdmin(admin.ModelAdmin):
    model = Account
    list_display = ['username', 'password']

class MessagesAdmin(admin.ModelAdmin):
    model = Messages
    list_display = ['sender', 'receiver' , 'message']

admin.site.register(Account, AccountAdmin)
admin.site.register(Messages, MessagesAdmin)