from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail, EmailMessage
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from jwt.utils import force_bytes
from rest_framework import viewsets, generics, status, permissions
from rest_framework.decorators import api_view, action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import *
from django.contrib.auth import authenticate, get_user_model
from .models import CustomUser
from django.contrib.auth import logout
from django.http import JsonResponse
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView, PasswordResetDoneView, \
    PasswordResetCompleteView
from django.urls import reverse_lazy



class CustomUserListCreateAPIView(generics.ListCreateAPIView):
    permission_classes = [AllowAny]
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


class CustomUserRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [AllowAny]
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


class SalarySlipViewSet(viewsets.ModelViewSet):
    queryset = SalarySlip.objects.all()
    permission_classes = [AllowAny]
    serializer_class = SalarySlipSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_staff or user.role == 'admin':  # Assuming 'admin' role allows access to all salary slips
            return SalarySlip.objects.all().order_by('-upload_date')
        return SalarySlip.objects.filter(user=user).order_by('-upload_date')

class NotificationViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer



class LeaveRequestViewSet(viewsets.ModelViewSet):
    serializer_class = LeaveRequestSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        user = self.request.user
        return LeaveRequest.objects.filter(employee=user).order_by('-start_date')

    def perform_create(self, serializer):
        serializer.save(employee=self.request.user)



class AdminLeaveRequestViewSet(viewsets.ModelViewSet):
    serializer_class = LeaveRequestSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        return LeaveRequest.objects.all().order_by('-start_date')

    def perform_update(self, serializer):
        instance = serializer.save()

        # Check if the status has changed
        if 'status' in serializer.validated_data:
            new_status = serializer.validated_data['status']
            if new_status != instance.status:
                user = instance.employee
                subject = 'Leave Request Status Updated'
                message = f'Your leave request has been {new_status} by the admin.'
                try:
                    send_mail(subject, message, 'from@example.com', [user.email])
                except Exception as e:
                    print(f"An error occurred while sending email: {e}")

        return super().perform_update(serializer)

    @action(detail=True, methods=['post'])
    def approve_leave_request(self, request, pk=None):
        leave_request = self.get_object()
        leave_request.status = 'approved'
        leave_request.save()
        user = leave_request.employee
        subject = 'Leave Request Approved'
        message = 'Your leave request has been approved by the admin.'
        try:
            send_mail(subject, message, 'shazil03144426622@gmail.com', [user.email])
        except Exception as e:
            print(f"An error occurred while sending email: {e}")
        return Response({'message': 'Leave request approved successfully.'})

    @action(detail=True, methods=['post'])
    def decline_leave_request(self, request, pk=None):
        leave_request = self.get_object()
        leave_request.status = 'declined'
        leave_request.save()
        user = leave_request.employee
        subject = 'Leave Request Declined'
        message = 'Your leave request has been declined by the admin.'
        try:
            send_mail(subject, message, 'shazil03144426622@gmail.com', [user.email])
        except Exception as e:
            print(f"An error occurred while sending email: {e}")
        return Response({'message': 'Leave request declined successfully.'})

class UserLoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        username = data.get('username')
        password = data.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:

            refresh = RefreshToken.for_user(user)
            refresh_token = str(refresh)

            profile_photo_url = None
            if user.profile_photo:
                profile_photo_url = request.build_absolute_uri(user.profile_photo.url)

            return Response({
                'access': str(refresh.access_token),
                'refresh': refresh_token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'designation': user.designation,
                    'role': user.role,
                    'email': user.email,
                    'profile_photo_url': profile_photo_url,
                    'active_status': user.is_active

                }
            })
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

class UserRegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User created successfully.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogoutAPIView(APIView):
    def post(self, request):
        if request.method == 'POST':
            logout(request)
            return JsonResponse({'message': 'User logged out successfully.'})
        else:
            return JsonResponse({'error': 'Method not allowed.'}, status=405)


class ContactView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            name = serializer.validated_data['name']
            email = serializer.validated_data['email']
            phoneno = str(serializer.validated_data['phoneno'])
            message = serializer.validated_data['message']

            # Create the full message
            full_message = f"Name: {name}\nPhone: {phoneno}\nMessage: {message}"

            try:
                # Send the message to your email
                send_mail(
                    'New Contact Form Submission',
                    full_message,
                    'shazil03144426622@gmail.com',
                    ['shazil03144426622@gmail.com'],
                    fail_silently=False,
                )

                # Send a thank you message to the user
                send_mail(
                    'Thank you for contacting us',
                    f'Thank you for reaching out, {name}!\n\nWe have received your message and will get back to you soon.',
                    'shazil03144426622@gmail.com',
                    [email],
                    fail_silently=False,
                )

                return Response({'message': 'Message sent successfully!'}, status=status.HTTP_200_OK)
            except Exception as e:
                print(f"An error occurred: {e}")
                return Response({'error': 'Failed to send message'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
def search_users(request):
    user_query = request.data.get('username', '')

    if user_query:
        filtered_users = CustomUser.objects.filter(username__icontains=user_query)
    else:
        filtered_users = CustomUser.objects.all()

    serializer = CustomUserSerializer(filtered_users, many=True, context={'request': request})
    return Response(serializer.data)









from .forms import CustomPasswordResetForm

UserModel = get_user_model()

class CustomPasswordResetView(View):
    template_name = 'password_reset_form.html'  # Replace with your template path

    def get(self, request):
        form = CustomPasswordResetForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = CustomPasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = UserModel.objects.filter(email=email).first()
            if user:
                current_site = get_current_site(request)
                subject = render_to_string('password_reset_subject.txt', {
                    'site_name': current_site.name,
                })
                email_template = render_to_string('password_reset_email.html', {
                    'user': user,
                    'protocol': request.scheme,
                    'domain': current_site.domain,
                    'uidb64': urlsafe_base64_encode(force_bytes(str(user.pk))),
                    'token': default_token_generator.make_token(user),
                    'password_reset_timeout': user.get_password_reset_timeout(),
                })
                email = EmailMessage(
                    subject=f"Reset Your Password on {current_site.name}",
                    body=email_template,
                    from_email=None,  # Set your email address for sending
                    to=[email],
                )

                email.send()
            return render(request, 'password_reset_done.html')  # Replace with your template path
        return render(request, self.template_name, {'form': form})


class CustomPasswordResetConfirmView(View):
    template_name = 'password_reset_confirm.html'  # Replace with your template path

    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel.objects.get(pk=uid)
        except (TypeError, ValueError, UserModel.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            return render(request, self.template_name, {'form': CustomPasswordResetForm()})
        return redirect('password_reset_done')  # Replace with your password reset done URL

    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel.objects.get(pk=uid)
        except (TypeError, ValueError, UserModel.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            form = SetPasswordForm(user=user, data=request.POST)
            if form.is_valid():
                form.save()
                return redirect('password_reset_complete')
        else:
            form = SetPasswordForm()

        return render(request, self.template_name, {'form': form})


class CustomPasswordResetDoneView(View):
    template_name = 'password_reset_done.html'  # Replace with your template path

    def get(self, request):
        return render(request, self.template_name)


class CustomPasswordResetCompleteView(View):
    template_name = 'password_reset_complete.html'  # Replace with your template path

    def get(self, request):
        return render(request, self.template_name)