import { useEffect, useState } from "react";
import axios from "axios";

const useSystemUpdateStatus = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await axios.get("/api/system/update-check/");
        setData(response.data);
      } catch (err) {
        setError("Failed to fetch update status");
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();
  }, []);

  return { data, loading, error };
};

export default useSystemUpdateStatus;
