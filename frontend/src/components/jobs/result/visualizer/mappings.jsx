// This module includes the mapping from the backend params to the frontend components
import React from "react";

import { IconContext } from "react-icons";
import {
  AiFillLike,
  AiFillDislike,
  AiFillGithub,
  AiFillHeart,
  AiFillWarning,
  AiFillFire,
} from "react-icons/ai";
import { BsShieldFillCheck } from "react-icons/bs";
import { FaBiohazard } from "react-icons/fa";
import { SiVirustotal } from "react-icons/si";
import { RiAliensFill } from "react-icons/ri";

import { PUBLIC_URL } from "../../../../constants/environment";

export const iconMapping = Object.freeze({
  like: <AiFillLike />,
  dislike: <AiFillDislike />,
  heart: <AiFillHeart />,
  malware: <FaBiohazard />,
  warning: <AiFillWarning />,
  shield: <BsShieldFillCheck />,
  fire: <AiFillFire />,
  // external services
  virusTotal: (
    // eslint-disable-next-line react/jsx-no-constructed-context-values
    <IconContext.Provider value={{ color: "blue" }}>
      <div>
        <SiVirustotal />
      </div>
    </IconContext.Provider>
  ),
  otx: <RiAliensFill />,
  github: <AiFillGithub />,
  twitter: (
    // eslint-disable-next-line react/jsx-no-constructed-context-values
    <IconContext.Provider value={{ color: "#3399ff" }}>
      <div>
        <SiVirustotal />
      </div>
    </IconContext.Provider>
  ),
  hybridAnalysis: (
    <img
      className="px-1"
      title="Hybrid Analysis"
      src={`${PUBLIC_URL}/icons/hybrid-analysis-icon.png`}
      alt="Hybrid Analysis"
      width="30px"
      height="24px"
    />
  ),
  urlhaus: (
    <img
      className="px-1"
      title="UrlHaus"
      src={`${PUBLIC_URL}/icons/urlhaus-icon.png`}
      alt="UrlHaus"
      width="30px"
      height="24px"
    />
  ),
  google: (
    <img
      className="px-1"
      title="Google"
      src={`${PUBLIC_URL}/icons/google-icon.png`}
      alt="Google"
      width="30px"
      height="24px"
    />
  ),
  cloudflare: (
    <img
      className="px-1"
      title="Cloudflare"
      src={`${PUBLIC_URL}/icons/cloudflare-icon.png`}
      alt="Cloudflare"
      width="30px"
      height="24px"
    />
  ),
  quad9: (
    <img
      className="px-1"
      title="Quad9"
      src={`${PUBLIC_URL}/icons/quad9-icon.png`}
      alt="Quad9"
      width="30px"
      height="24px"
    />
  ),
});
