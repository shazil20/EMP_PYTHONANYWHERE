from rest_framework import serializers
from .models import CustomUser, SalarySlip, Notification, LeaveRequest

class CustomUserSerializer(serializers.ModelSerializer):
    profile_photo_url = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'password', 'first_name', 'last_name', 'phone_number',
            'profile_photo', 'profile_photo_url', 'role', 'designation', 'is_active'
        ]
        extra_kwargs = {
            'password': {'write_only': True},  # Ensure password is write-only
        }

    def get_profile_photo_url(self, obj):
        request = self.context.get('request')
        if request is not None and obj.profile_photo and hasattr(obj.profile_photo, 'url'):
            return request.build_absolute_uri(obj.profile_photo.url)
        return None

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = CustomUser(**validated_data)
        if password is not None:
            user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        instance = super().update(instance, validated_data)
        if password:
            instance.set_password(password)
            instance.save()
        return instance


class SalarySlipSerializer(serializers.ModelSerializer):
    class Meta:
        model = SalarySlip
        fields = '__all__'


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'


class LeaveRequestSerializer(serializers.ModelSerializer):
    employee = CustomUserSerializer(read_only=True)

    class Meta:
        model = LeaveRequest
        fields = '__all__'


class ContactSerializer(serializers.Serializer):
    email = serializers.EmailField()
    name = serializers.CharField(max_length=100)
    phoneno = serializers.CharField(max_length=20)
    message = serializers.CharField(max_length=1000)
