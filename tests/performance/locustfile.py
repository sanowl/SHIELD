"""
Performance testing with Locust for SHIELD API.
"""

from locust import HttpUser, task, between
import json


class ShieldAPIUser(HttpUser):
    """Simulated user for SHIELD API performance testing."""

    wait_time = between(1, 3)  # Wait 1-3 seconds between requests

    def on_start(self):
        """Called when a simulated user starts."""
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @task(3)
    def test_protect_endpoint(self):
        """Test the /api/v1/protect endpoint."""
        payload = {
            "text": "Hello, how are you today?",
            "model": "test-model",
            "context": {"user_id": "test_user", "session_id": "test_session"},
        }

        try:
            response = self.client.post(
                "/api/v1/protect",
                json=payload,
                headers=self.headers,
                catch_response=True,
            )

            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Got status code {response.status_code}")

        except Exception as e:
            # Handle case where API might not be running
            pass

    @task(2)
    def test_filter_output_endpoint(self):
        """Test the /api/v1/filter-output endpoint."""
        payload = {
            "output": "This is a test response.",
            "context": {"regulations": ["gdpr"], "content_policy": "standard"},
        }

        try:
            response = self.client.post(
                "/api/v1/filter-output",
                json=payload,
                headers=self.headers,
                catch_response=True,
            )

            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Got status code {response.status_code}")

        except Exception as e:
            # Handle case where API might not be running
            pass

    @task(1)
    def test_monitor_stats_endpoint(self):
        """Test the /api/v1/monitor/stats endpoint."""
        try:
            response = self.client.get(
                "/api/v1/monitor/stats", headers=self.headers, catch_response=True
            )

            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Got status code {response.status_code}")

        except Exception as e:
            # Handle case where API might not be running
            pass

    @task(1)
    def test_health_endpoint(self):
        """Test the health endpoint."""
        try:
            response = self.client.get("/health", catch_response=True)

            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Got status code {response.status_code}")

        except Exception as e:
            # Handle case where API might not be running
            pass
