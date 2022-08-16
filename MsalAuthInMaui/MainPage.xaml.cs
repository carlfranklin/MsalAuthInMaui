using Microsoft.Identity.Client;
using MsalAuthInMaui.MsalClient;

namespace MsalAuthInMaui
{
    public partial class MainPage : ContentPage
    {
        private string _accessToken = string.Empty;

        bool _isLoggedIn = false;
        public bool IsLoggedIn
        {
            get => _isLoggedIn;
            set
            {
                if (value == _isLoggedIn) return;
                _isLoggedIn = value;
                OnPropertyChanged(nameof(IsLoggedIn));
            }
        }

        public MainPage()
        {
            BindingContext = this;
            InitializeComponent();
            _ = Login();
        }

        private async void OnLoginButtonClicked(object sender, EventArgs e)
        {
            await Login().ConfigureAwait(false);
        }

        private async Task Login()
        {
            try
            {
                // Attempt silent login, and obtain access token.
                var result = await PCAWrapper.Instance.AcquireTokenSilentAsync(PCAWrapper.Scopes).ConfigureAwait(false);
                IsLoggedIn = true;

                // Set access token.
                _accessToken = result.AccessToken;

                // Display Access Token from AcquireTokenSilentAsync call.
                await ShowOkMessage("Access Token from AcquireTokenSilentAsync call", _accessToken).ConfigureAwait(false);
            }
            // A MsalUiRequiredException will be thrown, if this is the first attempt to login, or after logging out.
            catch (MsalUiRequiredException)
            {
                // Perform interactive login, and obtain access token.
                var result = await PCAWrapper.Instance.AcquireTokenInteractiveAsync(PCAWrapper.Scopes).ConfigureAwait(false);
                IsLoggedIn = true;

                // Set access token.
                _accessToken = result.AccessToken;

                // Display Access Token from AcquireTokenInteractiveAsync call.
                await ShowOkMessage("Access Token from AcquireTokenInteractiveAsync call", _accessToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                IsLoggedIn = false;
                await ShowOkMessage("Exception in AcquireTokenSilentAsync", ex.Message).ConfigureAwait(false);
            }
        }

        private async void OnLogoutButtonClicked(object sender, EventArgs e)
        {
            // Log out.
            _ = await PCAWrapper.Instance.SignOutAsync().ContinueWith(async (t) =>
            {
                await ShowOkMessage("Signed Out", "Sign out complete.").ConfigureAwait(false);
                IsLoggedIn = false;
                _accessToken = string.Empty;
            }).ConfigureAwait(false);
        }

        private async void OnGetWeatherForecastButtonClicked(object sender, EventArgs e)
        {
            // Call the Secure Web API to get the weatherforecast data.
            var weatherForecastData = await CallSecureWebApi(_accessToken).ConfigureAwait(false);

            // Show the data.
            if (weatherForecastData != string.Empty)
                await ShowOkMessage("WeatherForecast data", weatherForecastData).ConfigureAwait(false);
        }

        // Call the Secure Web API.
        private static async Task<string> CallSecureWebApi(string accessToken)
        {
            if (accessToken == string.Empty)
                return string.Empty;

            try
            {
                // Get the weather forecast data from the Secure Web API.
                var client = new HttpClient();

                // Create the request.
                var message = new HttpRequestMessage(HttpMethod.Get, "https://msalsecurewebapi.azurewebsites.net/weatherforecast");

                // Add the Authorization Bearer header.
                message.Headers.Add("Authorization", $"Bearer {accessToken}");

                // Send the request.
                var response = await client.SendAsync(message).ConfigureAwait(false);

                // Get the response.
                var responseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                // Return the response.
                return responseString;
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
        }

        private Task ShowOkMessage(string title, string message)
        {
            _ = Dispatcher.Dispatch(async () =>
            {
                await DisplayAlert(title, message, "OK").ConfigureAwait(false);
            });
            return Task.CompletedTask;
        }
    }
}