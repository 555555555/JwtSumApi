namespace JwtSumApi.Services
{
    using System.Text.Json;

    public class RoleMappingService
    {
        private readonly Dictionary<string, string> _roleMap;

        public RoleMappingService(string filePath)
        {
            if (!File.Exists(filePath))
            {
                _roleMap = new Dictionary<string, string>();
                return;
            }

            var json = File.ReadAllText(filePath);
            _roleMap = JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                       ?? new Dictionary<string, string>();
        }

        public string GetRoleForUser(string username)
        {
            return _roleMap.TryGetValue(username, out var role)
                ? role
                : "GitHubUser"; // default fallback
        }
    }
}
