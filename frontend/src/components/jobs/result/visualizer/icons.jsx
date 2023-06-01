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
import {
  BsFillCloudArrowUpFill,
  BsFillCreditCard2BackFill,
  BsFillInboxFill,
  BsFillInfoSquareFill,
  BsIncognito,
  BsShieldFillCheck,
  BsTwitter,
} from "react-icons/bs";
import { FaBiohazard, FaLock } from "react-icons/fa";
import { HiMagnifyingGlassCircle } from "react-icons/hi2";
import { ImExit } from "react-icons/im";
import { SiVirustotal } from "react-icons/si";
import { RiAlarmWarningFill, RiAliensFill } from "react-icons/ri";

import { GiLighthouse, GiRetroController } from "react-icons/gi";
import { HiFilter } from "react-icons/hi";
import {
  MdCloudSync,
  MdEmail,
  MdSignalWifiStatusbarConnectedNoInternet2,
} from "react-icons/md";
import { TbFishHook } from "react-icons/tb";
import { PUBLIC_URL } from "../../../../constants/environment";

const generalIcons = Object.freeze({
  info: <BsFillInfoSquareFill />,
  like: <AiFillLike />,
  dislike: <AiFillDislike />,
  heart: <AiFillHeart />,
  malware: <FaBiohazard />,
  warning: <AiFillWarning />,
  shield: <BsShieldFillCheck />,
  fire: <AiFillFire />,
  alarm: <RiAlarmWarningFill />,
  magnifyingGlass: <HiMagnifyingGlassCircle />,
  creditCard: <BsFillCreditCard2BackFill />,
  email: <MdEmail />,
  hook: <TbFishHook />,
  filter: <HiFilter />,
  incognito: <BsIncognito />,
  inbox: <BsFillInboxFill />,
  cloudUpload: <BsFillCloudArrowUpFill />,
  cloudSync: <MdCloudSync />,
  lighthouseOn: <GiLighthouse />,
  controller: <GiRetroController />,
  exit: <ImExit />,
  connection: <MdSignalWifiStatusbarConnectedNoInternet2 />,
  locker: <FaLock />,
  // external services
  virusTotal: (
    // eslint-disable-next-line react/jsx-no-constructed-context-values
    <IconContext.Provider value={{ color: "blue" }}>
      <SiVirustotal />
    </IconContext.Provider>
  ),
  otx: <RiAliensFill />,
  github: <AiFillGithub />,
  twitter: (
    // eslint-disable-next-line react/jsx-no-constructed-context-values
    <IconContext.Provider value={{ color: "#3399ff" }}>
      <BsTwitter />
    </IconContext.Provider>
  ),
  quokka: (
    <img
      className="px-1"
      title="Quokka"
      src={`${PUBLIC_URL}/icons/quokka-icon.png`}
      alt="Quokka"
      width="30px"
      height="24px"
    />
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

export function getIcon(iconCode) {
  // this is need because in case of empty string we avoid to create a span without an icon (it takes space in the UI)
  if (!iconCode) {
    return null;
  }
  const selectedIcon = generalIcons[iconCode];
  /* in case the icon is not defined previously we cannot check if the icons is a flag or an invalid text:
   we would need to known the code of all flags and it's too expensive
  */
  if (!selectedIcon) {
    return <span className={` mx-1 fi fi-${iconCode}`} />;
  }
  return selectedIcon;
}
