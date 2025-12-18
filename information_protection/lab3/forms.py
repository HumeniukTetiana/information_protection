from django import forms

class Lab3Form(forms.Form):
    file = forms.FileField(label="Виберіть файл")
    password = forms.CharField(widget=forms.PasswordInput, label="Парольна фраза")
    action = forms.ChoiceField(
        choices=[('encrypt', 'Зашифрувати'), ('decrypt', 'Розшифрувати')],
        label="Дія"
    )
