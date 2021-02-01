# Generated by Django 2.2.17 on 2021-02-01 18:46

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('shoppingcart', '0004_change_meta_options'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='certificateitem',
            name='course_enrollment',
        ),
        migrations.RemoveField(
            model_name='certificateitem',
            name='orderitem_ptr',
        ),
        migrations.RemoveField(
            model_name='coupon',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='couponredemption',
            name='coupon',
        ),
        migrations.RemoveField(
            model_name='couponredemption',
            name='order',
        ),
        migrations.RemoveField(
            model_name='couponredemption',
            name='user',
        ),
        migrations.RemoveField(
            model_name='courseregcodeitem',
            name='orderitem_ptr',
        ),
        migrations.DeleteModel(
            name='CourseRegCodeItemAnnotation',
        ),
        migrations.RemoveField(
            model_name='courseregistrationcode',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='courseregistrationcode',
            name='invoice',
        ),
        migrations.RemoveField(
            model_name='courseregistrationcode',
            name='invoice_item',
        ),
        migrations.RemoveField(
            model_name='courseregistrationcode',
            name='order',
        ),
        migrations.RemoveField(
            model_name='courseregistrationcodeinvoiceitem',
            name='invoiceitem_ptr',
        ),
        migrations.RemoveField(
            model_name='donation',
            name='orderitem_ptr',
        ),
        migrations.RemoveField(
            model_name='donationconfiguration',
            name='changed_by',
        ),
        migrations.RemoveField(
            model_name='invoicehistory',
            name='invoice',
        ),
        migrations.RemoveField(
            model_name='invoiceitem',
            name='invoice',
        ),
        migrations.RemoveField(
            model_name='invoicetransaction',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='invoicetransaction',
            name='invoice',
        ),
        migrations.RemoveField(
            model_name='invoicetransaction',
            name='last_modified_by',
        ),
        migrations.RemoveField(
            model_name='order',
            name='user',
        ),
        migrations.RemoveField(
            model_name='orderitem',
            name='order',
        ),
        migrations.RemoveField(
            model_name='orderitem',
            name='user',
        ),
        migrations.RemoveField(
            model_name='paidcourseregistration',
            name='course_enrollment',
        ),
        migrations.RemoveField(
            model_name='paidcourseregistration',
            name='orderitem_ptr',
        ),
        migrations.DeleteModel(
            name='PaidCourseRegistrationAnnotation',
        ),
        migrations.RemoveField(
            model_name='registrationcoderedemption',
            name='course_enrollment',
        ),
        migrations.RemoveField(
            model_name='registrationcoderedemption',
            name='order',
        ),
        migrations.RemoveField(
            model_name='registrationcoderedemption',
            name='redeemed_by',
        ),
        migrations.RemoveField(
            model_name='registrationcoderedemption',
            name='registration_code',
        ),
        migrations.DeleteModel(
            name='CertificateItem',
        ),
        migrations.DeleteModel(
            name='Coupon',
        ),
        migrations.DeleteModel(
            name='CouponRedemption',
        ),
        migrations.DeleteModel(
            name='CourseRegCodeItem',
        ),
        migrations.DeleteModel(
            name='CourseRegistrationCode',
        ),
        migrations.DeleteModel(
            name='CourseRegistrationCodeInvoiceItem',
        ),
        migrations.DeleteModel(
            name='Donation',
        ),
        migrations.DeleteModel(
            name='DonationConfiguration',
        ),
        migrations.DeleteModel(
            name='Invoice',
        ),
        migrations.DeleteModel(
            name='InvoiceHistory',
        ),
        migrations.DeleteModel(
            name='InvoiceItem',
        ),
        migrations.DeleteModel(
            name='InvoiceTransaction',
        ),
        migrations.DeleteModel(
            name='Order',
        ),
        migrations.DeleteModel(
            name='OrderItem',
        ),
        migrations.DeleteModel(
            name='PaidCourseRegistration',
        ),
        migrations.DeleteModel(
            name='RegistrationCodeRedemption',
        ),
    ]
