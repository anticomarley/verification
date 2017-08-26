import django
import datetime
from django.db import models
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from datetime import date
from django.utils.translation import ugettext_lazy as _

from authtools.models import AbstractNamedUser

class UniversityInfo(models.Model):
	user = models.OneToOneField(settings.AUTH_USER_MODEL,
								related_name='+', on_delete=models.CASCADE, unique=True)
	institute_name = models.CharField(max_length=200)
	category = models.CharField(max_length=200)
	url = models.URLField(max_length=200, blank=False)
	contact = models.CharField(max_length=200)
	address = models.CharField(max_length=200)
	region = models.CharField(max_length=200)
	location = models.CharField(max_length=200)
	Country = models.CharField(max_length=200)
	verification_amount = models.IntegerField()
	photo = models.ImageField(upload_to='university_logo', default = 'univeristy_logo/no-img.jpg')
def get_university_info(user):
		return UniversityInfo.objects.get(user=user)

class StudentAlumniInfo(models.Model):
	user = models.OneToOneField(settings.AUTH_USER_MODEL,
								related_name='+', on_delete=models.CASCADE, unique=True)
	firstname = models.CharField(max_length=200)
	lastname = models.CharField(max_length=200)
	dateofbirth = models.DateField(auto_now_add=True, null=True, blank=True)
	contact = models.CharField(max_length=200)
	city = models.CharField(max_length=200)
	country = models.CharField(max_length=200)
	photo = models.ImageField(upload_to='profile_image')
def get_Corporate_info(user):
	return StudentAlumniInfo.objects.get(user=user)

class CorporateInfo(models.Model):
	user = models.OneToOneField(settings.AUTH_USER_MODEL,
								related_name='+', on_delete=models.CASCADE, unique=True)
	organization_name = models.CharField(max_length=200)
	url = models.URLField(max_length=200, blank=False)
	contact = models.CharField(max_length=200)
	Country = models.CharField(max_length=200)
	photo = models.ImageField(upload_to='profile_image')
def get_Corporate_info(user):
	return CorporateInfo.objects.get(user=user)

class DocumentSubcategory(models.Model):
	subcategory = models.CharField(max_length=200, unique=True)

	def __str__(self):              # __unicode__ on Python 2
		return self.subcategory

class DocumentCategory(models.Model):
	category = models.CharField(max_length=200, unique=True)
	member = models.ManyToManyField(DocumentSubcategory, through='UserDocuments')

	def __str__(self):              # __unicode__ on Python 2
		return self.category

class UserDocuments(models.Model):
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	category = models.ForeignKey(DocumentCategory, on_delete=models.CASCADE)
	subcategory = models.ForeignKey(DocumentSubcategory, on_delete=models.CASCADE)
	document_id = models.CharField(max_length=200, unique=True)
	document_name = models.CharField(max_length=200)
	description = models.CharField(max_length=200)
	date_created = models.DateTimeField(auto_now_add=True)
	document = models.FileField(upload_to='documents')

class VerifiedCertificates(models.Model):
	user = models.ForeignKey(StudentAlumniInfo)
	full_name = models.CharField(max_length=200)
	reg_no = models.CharField(max_length=200)
	verification_no = models.CharField(max_length=200, unique=True)
	course = models.CharField(max_length=200)
	specialization = models.CharField(max_length=200)
	passing_date = models.DateField()
	cgpa = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=4)
	class_obtained = models.CharField(max_length=200)
	institution_name = models.CharField(max_length=200)
	institution_email = models.ForeignKey(UniversityInfo)
	verifier_name = models.CharField(max_length=200)
	verifier_email = models.EmailField()
	verified_date = models.DateTimeField(auto_now_add=True)
	verification_status = models.CharField(max_length=200)
	certificate = models.FileField(upload_to='verified_certificates')

class CertificateVerificationHistory(models.Model):
	document_id = models.ForeignKey(UserDocuments, to_field='document_id')
	transaction_no = models.CharField(max_length=200)
	document_name = models.CharField(max_length=200)
	request_date = models.DateTimeField(default=timezone.now)
	institution_email = models.ForeignKey(UniversityInfo)
	verifier_name = models.CharField(max_length=200)
	verifier_email = models.EmailField()
	verification_status = models.CharField(max_length=200)

class CertificateSubmittionHistory(models.Model):
	user = models.ForeignKey(StudentAlumniInfo)
	organization_name = models.CharField(max_length=200)
	organization_email = models.EmailField()
	verification_no = models.CharField(max_length=200)
	share_id = models.CharField(max_length=200)
	reference_no = models.ForeignKey(VerifiedCertificates, to_field='verification_no')
	auth_code = models.CharField(max_length=200)
	submittion_date = models.DateTimeField(auto_now_add=True)
	submittion_status = models.CharField(max_length=200)
	verification_status = models.CharField(max_length=200)


	
		