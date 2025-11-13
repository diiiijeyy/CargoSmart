/* =================== Configuration =================== */
const API_BASE_URL = window.location.origin.includes("localhost")
  ? "http://localhost:5001"
  : "https://tslfreightmovers.com";

// Get email from hidden field or modal data
function getVerifyEmail() {
  const hidden = document.getElementById("verifyEmail");
  if (hidden && hidden.value.trim()) return hidden.value.trim();

  const modal = document.getElementById("verifyModal");
  if (modal && modal.dataset.email) return modal.dataset.email.trim();

  return "";
}

// Get verification code from 6 OTP boxes
function getVerificationCode() {
  const otpInputs = document.querySelectorAll(".otp-input");
  if (!otpInputs.length) return "";
  return Array.from(otpInputs)
    .map((input) => input.value.trim())
    .join("");
}

/* =================== Main Logic =================== */
document.addEventListener("DOMContentLoaded", () => {
  const showSignupBtn = document.getElementById("showSignup");
  const showLoginBtn = document.getElementById("goToLogin");
  const forgotPasswordBtn = document.getElementById("forgotPasswordBtn");
  const backToLoginBtn = document.getElementById("backToLogin");
  const backToLoginLink = document.getElementById("backToLoginLink");
  const backToLoginFromNew = document.getElementById("backToLoginFromNew");

  const loginContainer = document.getElementById("login-container");
  const signupContainer = document.getElementById("signup-container");
  const resetPasswordContainer = document.getElementById(
    "reset-password-container"
  );

  function showOnly(container) {
    document
      .querySelectorAll(".card.shadow.p-4")
      .forEach((c) => c.classList.add("d-none"));
    if (container) container.classList.remove("d-none");
  }

  showSignupBtn?.addEventListener("click", () => showOnly(signupContainer));
  showLoginBtn?.addEventListener("click", () => showOnly(loginContainer));
  forgotPasswordBtn?.addEventListener("click", () =>
    showOnly(resetPasswordContainer)
  );
  backToLoginBtn?.addEventListener("click", () => showOnly(loginContainer));

  /* =================== Login =================== */
  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const input = document.getElementById("username").value.trim();
      const password = document.getElementById("password").value.trim();
      if (!input || !password) return;

      const alertMessage = document.getElementById("alertMessage");
      const attemptCountEl = document.getElementById("attemptCount");
      const submitBtn = loginForm.querySelector("button[type='submit']");

      try {
        submitBtn.disabled = true;

        const res = await fetch(`${API_BASE_URL}/api/login`, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input, password }),
        });

        const data = await res.json();

        if (res.ok) {
          if (data.user)
            localStorage.setItem("user", JSON.stringify(data.user));
          if (alertMessage) alertMessage.classList.add("d-none");
          if (attemptCountEl) attemptCountEl.textContent = "0";
          sessionStorage.removeItem("welcomeShown");

          switch (data.user.role) {
            case "admin":
              window.location.href = "./admin/admin.html";
              break;
            case "client":
              window.location.href = "./client/pages/clientdashboard.html";
              break;
            case "operational_manager":
              window.location.href = "./om/om_dashboard.html";
              break;
            case "accounting":
              window.location.href = "./accounting/accounting-dashboard.html";
              break;
            default:
              window.location.href = "dashboard.html";
          }
        } else if (res.status === 429) {
          const message = data.error || "Your account is temporarily locked.";
          const secondsMatch = message.match(/(\d+)\s*seconds?/i);
          const seconds = secondsMatch ? parseInt(secondsMatch[1], 10) : 60;

          const modalMessage = document.getElementById("lockoutMessage");
          if (modalMessage) {
            modalMessage.textContent = `Too many failed attempts. Please wait ${seconds} seconds or reset your password.`;
          }

          const lockoutModalEl = document.getElementById("lockoutModal");
          const lockoutModal = new bootstrap.Modal(lockoutModalEl);
          lockoutModal.show();

          let remaining = seconds;
          const timer = setInterval(() => {
            remaining--;
            if (remaining <= 0) {
              clearInterval(timer);
              if (modalMessage)
                modalMessage.textContent = "You can now try logging in again.";
            } else {
              modalMessage.textContent = `Too many failed attempts. Please wait ${remaining} seconds or reset your password.`;
            }
          }, 1000);

          const resetBtn = document.getElementById("resetBtn");
          const waitBtn = document.getElementById("waitBtn");

          if (resetBtn) {
            resetBtn.onclick = () => {
              lockoutModal.hide();
              showOnly(resetPasswordContainer);
              const resetEmailInput = document.getElementById("resetEmail");
              if (resetEmailInput) resetEmailInput.value = input;
            };
          }

          if (waitBtn) {
            waitBtn.onclick = () => lockoutModal.hide();
          }
        } else {
          if (alertMessage) {
            alertMessage.textContent =
              data.error || "Please check Email and Password.";
            alertMessage.classList.remove("d-none");
          }

          const match = data.error?.match(/Attempts left:\s*(\d+)/i);
          if (match && attemptCountEl)
            attemptCountEl.textContent = `${5 - match[1]}`;
        }
      } catch (err) {
        console.error("Login error:", err);
        if (alertMessage) {
          alertMessage.textContent = "Network error. Please try again.";
          alertMessage.classList.remove("d-none");
        }
      } finally {
        submitBtn.disabled = false;
      }
    });
  }

  // =================== Toast Helper ===================
  function showValidationToast(message) {
    const toastEl = document.getElementById("validationToast");
    if (!toastEl) return;

    const toastBody = toastEl.querySelector(".toast-body");
    toastBody.textContent = message;

    // 🔴 Make it red color
    toastEl.className =
      "toast align-items-center text-bg-danger border-0 position-fixed top-0 end-0 m-3";

    // Show toast (for 3 seconds)
    const toast = new bootstrap.Toast(toastEl, { delay: 3000 });
    toast.show();
  }

  /* =================== Sign Up =================== */
  const signupForm = document.getElementById("signupForm");
  if (signupForm) {
    signupForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const company_name = document
        .getElementById("signupCompanyName")
        .value.trim();
      const contact_person = document
        .getElementById("signupContactPerson")
        .value.trim();
      const contact_number =
        document.getElementById("signupContactNumber").dataset.full ||
        document.getElementById("signupContactNumber").value.trim();
      const email = document.getElementById("signupEmail").value.trim();
      const password = document.getElementById("signupPassword").value.trim();
      const confirmPassword = document
        .getElementById("signupConfirmPassword")
        .value.trim();
      const address = document.getElementById("signupAddress").value.trim();

      const passwordInput = document.getElementById("signupPassword");
      const confirmPasswordInput = document.getElementById(
        "signupConfirmPassword"
      );
      const passwordError = document.getElementById("passwordError");
      const confirmPasswordError = document.getElementById(
        "confirmPasswordError"
      );

      passwordInput.classList.remove("is-invalid");
      confirmPasswordInput.classList.remove("is-invalid");
      passwordError.textContent = "";
      confirmPasswordError.textContent = "";

      // 🔄 Remove previous inline errors
      document.querySelectorAll(".inline-error").forEach((el) => el.remove());
      document
        .getElementById("signupCompanyName")
        .classList.remove("is-invalid");
      document
        .getElementById("signupContactPerson")
        .classList.remove("is-invalid");

      let hasEmpty = false;
      [
        "signupCompanyName",
        "signupContactPerson",
        "signupContactNumber",
        "signupEmail",
        "signupPassword",
        "signupConfirmPassword",
        "signupAddress",
      ].forEach((id) => {
        const field = document.getElementById(id);
        const group = field.closest(".input-group");
        if (!field.value.trim()) {
          hasEmpty = true;
          if (group) group.classList.add("invalid-field");
        } else {
          if (group) group.classList.remove("invalid-field");
        }
      });

      if (hasEmpty) return;

      const termsCheckbox = document.getElementById("termsCheckbox");
      if (!termsCheckbox.checked) {
        termsCheckbox.classList.add("invalid-checkbox");
        termsCheckbox.style.animation = "shake 0.3s";
        setTimeout(() => (termsCheckbox.style.animation = ""), 400);
        return;
      } else {
        termsCheckbox.classList.remove("invalid-checkbox");
      }

      /* =================== Name Validation =================== */
      const nameNumberPattern = /\d/;
      const companyNameField = document.getElementById("signupCompanyName");
      const contactPersonField = document.getElementById("signupContactPerson");

      let hasError = false;

      // ✅ Always show validation message directly below (outside) input box
      const showErrorOutsideGroup = (inputEl, message) => {
        const fieldWrapper =
          inputEl.closest(".input-group") ||
          inputEl.closest(".form-group") ||
          inputEl.closest(".mb-1") ||
          inputEl.parentElement;

        if (!fieldWrapper) return;

        inputEl.classList.add("is-invalid");

        // Remove any previous error for this input
        const oldError = fieldWrapper.parentElement.querySelector(
          `.inline-error[data-for='${inputEl.id}']`
        );
        if (oldError) oldError.remove();

        // Create error <small>
        const errorMsg = document.createElement("small");
        errorMsg.className = "inline-error text-danger";
        errorMsg.dataset.for = inputEl.id;
        errorMsg.textContent = message;

        // ✅ Insert completely outside the input-group (below it)
        fieldWrapper.insertAdjacentElement("afterend", errorMsg);
      };

      /* =================== Password Validation =================== */
      const passwordPattern =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

      if (!passwordPattern.test(password)) {
        passwordInput.classList.add("is-invalid");
        passwordError.textContent =
          "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.";
        return;
      }

      if (password !== confirmPassword) {
        passwordInput.classList.add("is-invalid");
        confirmPasswordInput.classList.add("is-invalid");
        confirmPasswordError.textContent = "Passwords do not match.";
        return;
      }

      /* =================== Contact Number Validation (Philippines) =================== */
      const contactNumberPattern = /^(?:\+639\d{9}|09\d{9})$/; // accepts +639XXXXXXXXX or 09XXXXXXXXX
      const contactNumberField = document.getElementById("signupContactNumber");
      const phoneError = document.getElementById("phoneError");

      phoneError.textContent = ""; // clear any previous message
      contactNumberField.classList.remove("is-invalid");

      if (!contactNumberPattern.test(contact_number)) {
        contactNumberField.classList.add("is-invalid");
        phoneError.textContent = "Please provide a valid mobile number.";
        return;
      }

      /* =================== Signup API Request =================== */
      try {
        const res = await fetch(`${API_BASE_URL}/api/client/signup`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            company_name,
            contact_person,
            contact_number,
            email,
            password,
            address,
          }),
        });

        const data = await res.json();

        if (res.ok) {
          signupForm.reset();

          // open verification modal
          const modalEl = document.getElementById("verifyModal");
          const hiddenEmail = document.getElementById("verifyEmail");
          hiddenEmail.value = email;
          modalEl.dataset.email = email;

          let verifyModal = bootstrap.Modal.getInstance(modalEl);
          if (!verifyModal) {
            verifyModal = new bootstrap.Modal(modalEl);
          }
          verifyModal.show();

          startResendTimer();
        } else {
          if (
            data.error &&
            data.error.toLowerCase().includes("already registered")
          ) {
            const toastEl = document.getElementById("emailExistsToast");
            if (toastEl) {
              const toast = new bootstrap.Toast(toastEl);
              toast.show();
            }
          } else {
            alert(data.error || "Signup failed. Please try again.");
          }
        }
      } catch (err) {
        console.error("Signup error:", err);
        alert("An error occurred. Please try again.");
      }
    });
  }

  /* =================== Validation Helpers =================== */

  // Mark an input + its group invalid
  function markInvalid(inputEl) {
    if (!inputEl) return;
    inputEl.classList.add("is-invalid");

    const group = inputEl.closest(".input-group");
    if (group) group.classList.add("invalid-field");
  }

  // Clear red border while typing
  signupForm.querySelectorAll("input, textarea, select").forEach((field) => {
    field.addEventListener("input", () => {
      field.classList.remove("is-invalid");
      const group = field.closest(".input-group");
      if (group) group.classList.remove("invalid-field");
    });
  });

  /* =================== Block Numbers in Contact Person Only =================== */
  const contactPersonField = document.getElementById("signupContactPerson");

  if (contactPersonField) {
    // Prevent typing numbers
    contactPersonField.addEventListener("beforeinput", (e) => {
      if (e.data && /\d/.test(e.data)) e.preventDefault(); // block digits only
    });

    // Clean pasted text (remove digits)
    contactPersonField.addEventListener("input", () => {
      contactPersonField.value = contactPersonField.value.replace(/\d/g, "");
    });
  }

  /* =================== Block letters and symbols in phone input =================== */
  const contactNumberInput = document.getElementById("signupContactNumber");
  if (contactNumberInput) {
    contactNumberInput.addEventListener("beforeinput", function (e) {
      // Allow only digits, backspace, delete, arrow keys, and basic editing keys
      if (
        e.data &&
        !/^\d+$/.test(e.data) && // not a digit
        e.inputType !== "deleteContentBackward" &&
        e.inputType !== "deleteContentForward"
      ) {
        e.preventDefault(); // block non-digit input
      }
    });

    // Clean any pasted value instantly
    contactNumberInput.addEventListener("input", function () {
      this.value = this.value.replace(/\D/g, ""); // remove all non-digits
    });
  }

  /* =================== Verify Code =================== */
  const verifyForm = document.getElementById("verifyForm");
  if (verifyForm) {
    verifyForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const email = getVerifyEmail();
      const code = getVerificationCode();

      if (!email) {
        alert("Missing email. Please sign up again.");
        return;
      }
      if (!code || code.length !== 6) {
        alert("Please enter the 6-digit verification code.");
        return;
      }

      const submitBtn = verifyForm.querySelector('button[type="submit"]');
      if (submitBtn) submitBtn.disabled = true;

      try {
        const res = await fetch(`${API_BASE_URL}/api/client/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, code }),
        });

        const data = await res.json();

        if (res.ok) {
          const verifyModalEl = document.getElementById("verifyModal");
          const vm =
            bootstrap.Modal.getInstance(verifyModalEl) ||
            new bootstrap.Modal(verifyModalEl);
          vm.hide();

          // Clear OTP boxes
          document
            .querySelectorAll(".otp-input")
            .forEach((b) => (b.value = ""));

          // ✅ Show success modal instead of toast
          showSuccessModal(
            "Email Verified",
            "Your email has been successfully verified! You can now log in to your account."
          );
        } else {
          // invalid otp feedback
          const otpInputs = document.querySelectorAll(".otp-input");
          otpInputs.forEach((input) => {
            input.classList.add("invalid");
            setTimeout(() => input.classList.remove("invalid"), 1000);
          });
        }
      } catch (err) {
        console.error("Verification error:", err);
        alert("Network error during verification. Please try again.");
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }

  /* =================== Resend Code =================== */
  const verifyResendCodeBtn = document.getElementById("resendCodeBtn");
  const resetResendCodeBtn = document.getElementById("resetResendCodeBtn");

  function startResendTimer(button) {
    if (!button) return;
    let countdown = 30;
    button.textContent = `Resend Code (${countdown}s)`;
    button.classList.add("disabled");

    const timer = setInterval(() => {
      countdown--;
      button.textContent =
        countdown > 0 ? `Resend Code (${countdown}s)` : "Resend Code";
      if (countdown <= 0) {
        clearInterval(timer);
        button.classList.remove("disabled");
      }
    }, 1000);
  }

  verifyResendCodeBtn?.addEventListener("click", async (e) => {
    e.preventDefault();
    if (verifyResendCodeBtn.classList.contains("disabled")) return;

    const email = getVerifyEmail();
    if (!email) return alert("No email found. Please sign up again.");

    try {
      const res = await fetch(`${API_BASE_URL}/api/client/resend-code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const data = await res.json();

      if (res.ok) {
        const toastEl = document.getElementById("resendCodeToast");
        if (toastEl) new bootstrap.Toast(toastEl).show();
        startResendTimer(verifyResendCodeBtn);
      } else {
        alert(data.error || "Failed to resend verification code.");
      }
    } catch (err) {
      console.error("Resend verification code error:", err);
      alert("Network error while resending verification code.");
    }
  });

  resetResendCodeBtn?.addEventListener("click", async (e) => {
    e.preventDefault();
    if (resetResendCodeBtn.classList.contains("disabled")) return;

    const email = document.getElementById("resetCodeEmail")?.value.trim();
    if (!email) return alert("No email found. Please try again.");

    try {
      const res = await fetch(`${API_BASE_URL}/api/send-reset-code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const data = await res.json();

      if (res.ok) {
        const toastEl = document.getElementById("resendCodeToast");
        if (toastEl) new bootstrap.Toast(toastEl).show();
        startResendTimer(resetResendCodeBtn);
      } else {
        alert(data.error || "Failed to resend reset code.");
      }
    } catch (err) {
      console.error("Resend reset code error:", err);
      alert("Network error while resending reset code.");
    }
  });

  /* =================== GOOGLE SIGN-IN =================== */
  window.handleCredentialResponse = async function (response) {
    if (!response?.credential) return console.warn("No Google credential.");

    try {
      const res = await fetch(`${API_BASE_URL}/auth/google`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ token: response.credential }),
      });
      const data = await res.json();

      if (res.ok && data.success) {
        if (data.user) localStorage.setItem("user", JSON.stringify(data.user));
        if (data.token) localStorage.setItem("token", data.token);

        if (data.user.role === "client") {
          window.location.href = "./client/pages/clientdashboard.html";
        } else {
          alert("Google login is only for clients.");
        }
      } else {
        alert(data.error || "Google login failed!");
      }
    } catch (err) {
      console.error("Google login error:", err);
      alert("Google login failed. Try again.");
    }
  };

  /* =================== Log Out =================== */
  const logoutBtn = document.getElementById("logoutBtn");
  logoutBtn?.addEventListener("click", async () => {
    try {
      await fetch(
        `https://caiden-recondite-psychometrically.ngrok-free.dev/api/logout`,
        { method: "POST", credentials: "include" }
      );
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      window.location.href = "index.html";
    } catch (err) {
      console.error("Logout error:", err);
      alert("An error occurred while logging out.");
    }
  });
});

/* =================== OTP Auto Move code =================== */
document.querySelectorAll(".otp-input").forEach((input, i, arr) => {
  input.addEventListener("input", (e) => {
    if (e.target.value && i < arr.length - 1) arr[i + 1].focus();
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Backspace" && !input.value && i > 0) arr[i - 1].focus();
  });
});

/* =================== Preloader =================== */
window.addEventListener("load", function () {
  const preloader = document.getElementById("preloader");
  if (preloader) {
    preloader.style.opacity = "0";
    preloader.style.visibility = "hidden";
    setTimeout(() => preloader.remove(), 600);
  }
});

document.querySelectorAll(".code-box").forEach((box, i, arr) => {
  box.addEventListener("input", (e) => {
    if (e.target.value && i < arr.length - 1) arr[i + 1].focus();
  });
  box.addEventListener("keydown", (e) => {
    if (e.key === "Backspace" && !box.value && i > 0) arr[i - 1].focus();
  });
});

function showToast(message, type = "info") {
  const toastEl = document.getElementById("resetToast");
  const toastBody = document.getElementById("resetToastMessage");

  // set color
  toastEl.className = `toast align-items-center text-bg-${type} border-0`;
  toastBody.textContent = message;

  const toast = new bootstrap.Toast(toastEl);
  toast.show();
}

/* =================== Reset Password =================== */
// Elements
const sendResetCodeBtn = document.getElementById("sendResetCodeBtn");
const resetCodeForm = document.getElementById("resetCodeForm");
const newPasswordForm = document.getElementById("newPasswordForm");

/* =================== Send Reset Code =================== */
if (sendResetCodeBtn) {
  sendResetCodeBtn.addEventListener("click", async () => {
    const emailInput = document.getElementById("resetRequestEmail");
    const emailGroup = emailInput.closest(".input-group");
    const emailError = document.getElementById("resetEmailError");
    const email = emailInput.value.trim();

    // Reset states
    emailGroup?.classList.remove("invalid-field", "is-valid");
    if (emailError) emailError.textContent = "";

    // Empty email
    if (!email) {
      emailGroup?.classList.add("invalid-field");
      if (emailError)
        emailError.textContent = "Please enter your email address.";
      emailInput.focus();
      return;
    }

    try {
      const res = await fetch(`${API_BASE_URL}/api/send-reset-code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await res.json();

      if (res.ok) {
        const resetCodeModalEl = document.getElementById("resetCodeModal");
        const existingModal = bootstrap.Modal.getInstance(resetCodeModalEl);

        // Close any other open modals
        document.querySelectorAll(".modal.show").forEach((modal) => {
          const modalInstance = bootstrap.Modal.getInstance(modal);
          if (modalInstance && modal !== resetCodeModalEl) modalInstance.hide();
        });

        // Only show if not already visible
        if (!resetCodeModalEl.classList.contains("show")) {
          document.getElementById("resetCodeEmail").value = email;
          (existingModal || new bootstrap.Modal(resetCodeModalEl)).show();
        }

        emailGroup?.classList.add("is-valid");
        setTimeout(() => emailGroup?.classList.remove("is-valid"), 2000);
      } else {
        emailGroup?.classList.add("invalid-field");
        if (emailError)
          emailError.textContent =
            data.error || "Unable to send reset code. Please try again.";
      }
    } catch (err) {
      console.error("Send Reset Code Error:", err);
      emailGroup?.classList.add("invalid-field");
      if (emailError)
        emailError.textContent = "Network error. Please try again.";
    }
  });
}

/* =================== Veify Code =================== */
if (resetCodeForm) {
  resetCodeForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = document.getElementById("resetCodeEmail").value.trim();
    const otpInputs = document.querySelectorAll("#resetCodeForm .otp-input");
    const code = Array.from(otpInputs)
      .map((i) => i.value.trim())
      .join("");

    // Remove any existing error text
    const existingError = document.getElementById("resetCodeErrorText");
    if (existingError) existingError.remove();

    if (!code || code.length !== 6) {
      otpInputs.forEach((input) => {
        input.classList.add("invalid");
        setTimeout(() => input.classList.remove("invalid"), 1000);
      });
      return;
    }

    try {
      const res = await fetch(`${API_BASE_URL}/api/check-reset-code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, resetCode: code }),
      });

      const data = await res.json();

      if (res.ok) {
        const resetModal = bootstrap.Modal.getInstance(
          document.getElementById("resetCodeModal")
        );
        resetModal.hide();
        setTimeout(() => {
          new bootstrap.Modal(
            document.getElementById("newPasswordModal")
          ).show();
        }, 400);
      } else {
        otpInputs.forEach((input) => {
          input.classList.add("invalid");
          setTimeout(() => input.classList.remove("invalid"), 1000);
        });
      }
    } catch (err) {
      console.error("Verify code error:", err);
      otpInputs.forEach((input) => {
        input.classList.add("invalid");
        setTimeout(() => input.classList.remove("invalid"), 1000);
      });
    }
  });
}

/* =================== Create New Password =================== */
if (newPasswordForm) {
  newPasswordForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = document.getElementById("resetCodeEmail").value.trim();
    const resetCode = Array.from(
      document.querySelectorAll("#resetCodeForm .otp-input")
    )
      .map((i) => i.value.trim())
      .join("");
    const newPassword = document.getElementById("newPassword");
    const confirmPassword = document.getElementById("confirmNewPassword");

    // Remove previous invalid styles & feedback
    [newPassword, confirmPassword].forEach((f) =>
      f.classList.remove("is-invalid")
    );
    document
      .querySelectorAll(".password-feedback")
      .forEach((el) => el.remove());

    // Empty field validation
    if (!newPassword.value.trim() || !confirmPassword.value.trim()) {
      [newPassword, confirmPassword].forEach((f) =>
        f.classList.add("is-invalid")
      );
      return;
    }

    // ✅ Password pattern validation (same as sign up)
    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
    if (!passwordPattern.test(newPassword.value.trim())) {
      newPassword.classList.add("is-invalid");

      const feedback = document.createElement("div");
      feedback.className =
        "text-danger mt-1 ms-1 small fw-semibold password-feedback";
      feedback.textContent =
        "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.";
      newPassword.closest(".mb-3").appendChild(feedback);
      return;
    }

    // Password mismatch
    if (newPassword.value.trim() !== confirmPassword.value.trim()) {
      confirmPassword.classList.add("is-invalid");

      const feedback = document.createElement("div");
      feedback.className =
        "text-danger mt-1 ms-1 small fw-semibold password-feedback";
      feedback.textContent = "Passwords do not match.";
      confirmPassword.closest(".mb-3").appendChild(feedback);
      return;
    }

    try {
      const res = await fetch(`${API_BASE_URL}/api/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          resetCode,
          newPassword: newPassword.value.trim(),
        }),
      });

      const data = await res.json();

      if (res.ok) {
        const modal = bootstrap.Modal.getInstance(
          document.getElementById("newPasswordModal")
        );
        if (modal) modal.hide();

        // Show success modal
        showSuccessModal(
          "Password Reset Successful",
          "Your password has been updated successfully. You can now log in with your new password."
        );
      } else {
        alert(data.error || "Failed to reset password. Please try again.");
      }
    } catch (err) {
      console.error("Reset password error:", err);
      alert("Network error. Please try again.");
    }
  });
}

/* =================== Red Border validation =================== */
document.querySelectorAll("form").forEach((form) => {
  form.addEventListener("submit", (e) => {
    const requiredFields = form.querySelectorAll(
      "input[required], textarea[required], select[required]"
    );
    let allValid = true;

    requiredFields.forEach((field) => {
      const group = field.closest(".input-group");

      if (!field.value.trim()) {
        allValid = false;
        if (group) group.classList.add("invalid-field");
      } else {
        if (group) group.classList.remove("invalid-field");
      }
    });
    if (!allValid) {
      e.preventDefault();
      form.classList.add("was-submitted");
    }
  });

  form.querySelectorAll("input, textarea, select").forEach((field) => {
    field.addEventListener("input", () => {
      const group = field.closest(".input-group");
      if (field.value.trim() !== "" && group)
        group.classList.remove("invalid-field");
    });
  });
});

document.addEventListener("DOMContentLoaded", () => {
  const loginContainer = document.getElementById("login-container");
  const resetPasswordContainer = document.getElementById(
    "reset-password-container"
  );

  function showOnly(container) {
    document
      .querySelectorAll(".card.shadow.p-4")
      .forEach((c) => c.classList.add("d-none"));
    if (container) container.classList.remove("d-none");
  }

  // Use event delegation for hidden elements
  document.body.addEventListener("click", (e) => {
    if (e.target.closest("#backToLoginLink")) {
      e.preventDefault();
      showOnly(loginContainer);
    }

    if (e.target.closest("#backToLoginFromNew")) {
      e.preventDefault();
      const modal = bootstrap.Modal.getInstance(
        document.getElementById("newPasswordModal")
      );
      if (modal) modal.hide();
      showOnly(loginContainer);
    }
  });
});

/* =================== One Modal Only =================== */
document.addEventListener("show.bs.modal", function (event) {
  const openModals = document.querySelectorAll(".modal.show");
  openModals.forEach((modal) => {
    const instance = bootstrap.Modal.getInstance(modal);
    if (instance && modal !== event.target) {
      instance.hide();
    }
  });
});

/* -------------------------------
  Success Modal Helpers (Fixed Center Alignment)
--------------------------------*/
function ensureSuccessModal() {
  if (document.getElementById("successModal")) return;

  const modalHTML = `
    <div class="modal fade" id="successModal" tabindex="-1" aria-hidden="true">
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content success-modal border-0 shadow-lg">

          <!-- Header -->
          <div class="success-modal-header">
            <h5 class="modal-title fw-bold" id="successModalTitle">Success</h5>
          </div>

          <!-- Body -->
          <div class="success-modal-body d-flex flex-column justify-content-center align-items-center">
            <div class="success-modal-icon d-flex align-items-center justify-content-center">
              <i class="fas fa-check"></i>
            </div>
            <p class="mt-2 mb-0 fw-semibold" id="successModalMessage">
              Action completed successfully!
            </p>
          </div>

          <!-- Footer -->
          <div class="success-modal-footer">
            <button id="successModalOk" type="button" class="btn btn-ok rounded-pill fw-semibold">
              <i class="fas fa-check me-2"></i>OK
            </button>
          </div>

        </div>
      </div>
    </div>`;
  document.body.insertAdjacentHTML("beforeend", modalHTML);
}

function showSuccessModal(title, message, redirectUrl = "login.html") {
  ensureSuccessModal();

  document.getElementById("successModalTitle").innerText = title;
  document.getElementById("successModalMessage").innerText = message;

  const modalEl = document.getElementById("successModal");
  const modal = new bootstrap.Modal(modalEl);
  modal.show();

  const okBtn = document.getElementById("successModalOk");
  okBtn.addEventListener(
    "click",
    () => {
      modal.hide();
      setTimeout(() => (window.location.href = redirectUrl), 300);
    },
    { once: true }
  );
}
