import React from "react";

import { FallBackLoading } from "@certego/certego-ui";

import { useAuthStore } from "../../stores/useAuthStore";

export default function Logout() {
  // auth store
  const [loading, logoutUser] = useAuthStore(
    React.useCallback((state) => [state.loading, state.service.logoutUser], []),
  );

  React.useEffect(() => {
    if (!loading) {
      logoutUser();
    }
  }, [loading, logoutUser]);

  return <FallBackLoading text="Logging you out..." />;
}
