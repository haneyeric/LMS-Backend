# Generated by Django 5.1 on 2024-08-08 21:45

import django.db.models.deletion
import django.utils.timezone
import shortuuid.django_fields
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=100)),
                ('image', models.FileField(blank=True, default='category.jpg', null=True, upload_to='course-file')),
                ('active', models.BooleanField(default=True)),
                ('slug', models.SlugField(blank=True, null=True, unique=True)),
            ],
            options={
                'verbose_name_plural': 'Category',
                'ordering': ['title'],
            },
        ),
        migrations.CreateModel(
            name='Country',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('tax_rate', models.IntegerField(default=5)),
                ('active', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='Coupon',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=50)),
                ('discount', models.IntegerField(default=1)),
                ('active', models.BooleanField(default=False)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('used_by', models.ManyToManyField(blank=True, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='CartOrder',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sub_total', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('tax_fee', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('total', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('initial_total', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('saved', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('payment_status', models.CharField(choices=[('Paid', 'Paid'), ('Processing', 'Processing'), ('Failed', 'Failed')], default='Processing', max_length=100)),
                ('full_name', models.CharField(blank=True, max_length=100, null=True)),
                ('email', models.CharField(blank=True, max_length=100, null=True)),
                ('country', models.CharField(blank=True, max_length=100, null=True)),
                ('stripe_session_id', models.CharField(blank=True, max_length=1000, null=True)),
                ('oid', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('student', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('coupons', models.ManyToManyField(blank=True, to='api.coupon')),
            ],
            options={
                'ordering': ['-date'],
            },
        ),
        migrations.CreateModel(
            name='Course',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(blank=True, null=True, upload_to='course-file')),
                ('image', models.FileField(blank=True, null=True, upload_to='course-file')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True, null=True)),
                ('price', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('language', models.CharField(choices=[('English', 'English'), ('Spanish', 'Spanish'), ('French', 'French')], default='English', max_length=100)),
                ('level', models.CharField(choices=[('Beginner', 'Beginner'), ('Intemediate', 'Intemediate'), ('Advanced', 'Advanced')], default='Beginner', max_length=100)),
                ('platform_status', models.CharField(choices=[('Review', 'Review'), ('Disabled', 'Disabled'), ('Rejected', 'Rejected'), ('Draft', 'Draft'), ('Published', 'Published')], default='Published', max_length=100)),
                ('teacher_course_status', models.CharField(choices=[('Draft', 'Draft'), ('Disabled', 'Disabled'), ('Published', 'Published')], default='Published', max_length=100)),
                ('featured', models.BooleanField(default=False)),
                ('course_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('slug', models.SlugField(blank=True, null=True, unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('category', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='api.category')),
            ],
        ),
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('certificate_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
            ],
        ),
        migrations.CreateModel(
            name='CartOrderItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('price', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('tax_fee', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('total', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('initial_total', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('saved', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('applied_coupon', models.BooleanField(default=False)),
                ('oid', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('order', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='orderitem', to='api.cartorder')),
                ('coupons', models.ManyToManyField(blank=True, to='api.coupon')),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='order_item', to='api.course')),
            ],
            options={
                'ordering': ['-date'],
            },
        ),
        migrations.CreateModel(
            name='Cart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('price', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('tax_fee', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('total', models.DecimalField(decimal_places=2, default=0.0, max_digits=12)),
                ('country', models.CharField(blank=True, max_length=100, null=True)),
                ('cart_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='')),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
            ],
        ),
        migrations.CreateModel(
            name='Note',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(blank=True, max_length=1000, null=True)),
                ('note', models.TextField()),
                ('note_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Question_Answer',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(blank=True, max_length=1000, null=True)),
                ('qa_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-date'],
            },
        ),
        migrations.CreateModel(
            name='Question_Answer_Message',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField(blank=True, null=True)),
                ('qam_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('qa_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
                ('question', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.question_answer')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['date'],
            },
        ),
        migrations.CreateModel(
            name='Review',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('review', models.TextField()),
                ('rating', models.IntegerField(choices=[(1, '1 Star'), (2, '2 Star'), (3, '3 Star'), (4, '4 Star'), (5, '5 Star')], default=None)),
                ('reply', models.CharField(blank=True, max_length=1000, null=True)),
                ('active', models.BooleanField(default=False)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Teacher',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.FileField(blank=True, default='default.jpg', null=True, upload_to='course-file')),
                ('full_name', models.CharField(max_length=100)),
                ('bio', models.CharField(blank=True, max_length=100, null=True)),
                ('facebook', models.URLField(blank=True, null=True)),
                ('linkedin', models.URLField(blank=True, null=True)),
                ('about', models.TextField(blank=True, null=True)),
                ('country', models.CharField(blank=True, max_length=100, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('New Order', 'New Order'), ('New Review', 'New Review'), ('New Course Question', 'New Course Question'), ('Draft', 'Draft'), ('Course Published', 'Course Published'), ('Course Enrollment Completed', 'Course Enrollment Completed')], max_length=100)),
                ('seen', models.BooleanField(default=False)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('order', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='api.cartorder')),
                ('order_item', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='api.cartorderitem')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('review', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='api.review')),
                ('teacher', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='api.teacher')),
            ],
        ),
        migrations.CreateModel(
            name='EnrolledCourse',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enrollment_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
                ('order_item', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.cartorderitem')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('teacher', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='api.teacher')),
            ],
        ),
        migrations.AddField(
            model_name='course',
            name='teacher',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.teacher'),
        ),
        migrations.AddField(
            model_name='coupon',
            name='teacher',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='api.teacher'),
        ),
        migrations.AddField(
            model_name='cartorderitem',
            name='teacher',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.teacher'),
        ),
        migrations.AddField(
            model_name='cartorder',
            name='teachers',
            field=models.ManyToManyField(blank=True, to='api.teacher'),
        ),
        migrations.CreateModel(
            name='Variant',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=1000)),
                ('variant_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
            ],
        ),
        migrations.CreateModel(
            name='VariantItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=1000)),
                ('description', models.TextField(blank=True, null=True)),
                ('file', models.FileField(blank=True, null=True, upload_to='course-file')),
                ('duration', models.DurationField(blank=True, null=True)),
                ('content_duration', models.CharField(blank=True, max_length=1000, null=True)),
                ('preview', models.BooleanField(default=False)),
                ('variant_item_id', shortuuid.django_fields.ShortUUIDField(alphabet='1234567890', length=6, max_length=20, prefix='', unique=True)),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('variant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='variant_items', to='api.variant')),
            ],
        ),
        migrations.CreateModel(
            name='CompletedLesson',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
                ('variant_item', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.variantitem')),
            ],
        ),
        migrations.CreateModel(
            name='Wishlist',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.course')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
