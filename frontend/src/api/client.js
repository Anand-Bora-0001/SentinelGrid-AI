/**
 * SentinelGrid AI — API Client Utility
 * Wraps native fetch with auth, error handling, and JSON parsing.
 */

const getApiBase = () => {
  // Use relative path for production (served by FastAPI) or proxy in dev
  return "";
};

export const api = {
  // Auth state management
  setToken: (token) => localStorage.setItem("sg_token", token),
  getToken: () => localStorage.getItem("sg_token"),
  clearAuth: () => {
    localStorage.removeItem("sg_token");
    localStorage.removeItem("sg_user");
    localStorage.removeItem("sg_role");
  },
  setUser: (user) => localStorage.setItem("sg_user", user),
  getUser: () => localStorage.getItem("sg_user"),
  setRole: (role) => localStorage.setItem("sg_role", role),
  getRole: () => localStorage.getItem("sg_role"),

  headers: () => {
    const headers = {
      "Content-Type": "application/json",
    };
    const token = api.getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
  },

  handleResponse: async (response) => {
    if (response.status === 401) {
      api.clearAuth();
      // Redirect to login if on dashboard page
      if (window.location.pathname !== "/login" && !window.location.pathname.endsWith("login.html")) {
        window.location.href = "/login";
      }
      throw new Error("Unauthorized");
    }
    
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Request failed: ${response.statusText}`);
    }

    // Handles files or JSON
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      return response.json();
    }
    return response;
  },

  get: async (endpoint, params = {}) => {
    const query = Object.keys(params)
      .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
      .join("&");
    const url = `${getApiBase()}${endpoint}${query ? `?${query}` : ""}`;
    
    const response = await fetch(url, {
      method: "GET",
      headers: api.headers(),
    });
    return api.handleResponse(response);
  },

  post: async (endpoint, data = {}) => {
    const url = `${getApiBase()}${endpoint}`;
    const response = await fetch(url, {
      method: "POST",
      headers: api.headers(),
      body: JSON.stringify(data),
    });
    return api.handleResponse(response);
  },

  put: async (endpoint, data = {}) => {
    const url = `${getApiBase()}${endpoint}`;
    const response = await fetch(url, {
      method: "PUT",
      headers: api.headers(),
      body: JSON.stringify(data),
    });
    return api.handleResponse(response);
  },

  delete: async (endpoint) => {
    const url = `${getApiBase()}${endpoint}`;
    const response = await fetch(url, {
      method: "DELETE",
      headers: api.headers(),
    });
    return api.handleResponse(response);
  },

  // Direct login utility
  login: async (username, password) => {
    const params = new URLSearchParams();
    params.append("username", username);
    params.append("password", password);

    const response = await fetch(`${getApiBase()}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || "Authentication failed");
    }

    const data = await response.json();
    api.setToken(data.access_token);
    api.setUser(data.user);
    api.setRole(data.role);
    return data;
  }
};
