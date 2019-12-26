# XploitHunt- An Exploit Hunter

The “XploitHunt” tool is developed with the goal of cybernation of the work that
is to search the public exploit details using the CVE-IDs. In the present-day
version, the tool is capable of hunting the operation on various search engines
like Google, ZeroDay (which is mainly use Onion Websites) and website like
CVEDetails.

The “XploitHunt” tool is capable to export the specific and useful information
related to the CVE-ID from the Google Search by blacklisting the URLs and by
defining the proper Google Dork.

The primary function of the script is to collect the below details of the
searched CVE-ID:

-   Title

-   Description

-   CVSscore

-   Authentication

-   Vulnerability Type

-   Metasploit Modules

-   References

-   Exploit List

-   Google Results

-   0day Results

**MECHNISUM OF “XploitHunt”**

The tool “XploitHunt” is developed to search the exploit details from the below
search engines and websites by providing the CVE-ID:

-   Google (Search engine that is trained as per your search of CVE-ID)

-   Cvedetails[.]com
-   cxsecurity[.]com
-   zeroday (Onion website)

**Why one more exploit finder script?**

-   The tool “XploitHunt” saves time and effort involved in manual searching for
    results of a particular CVE-ID.

-   The tool "XploitHunt" is trained, to do google search intelligently by
    blacklisting the unwanted websites

-   It is smart enough to search by only providing google dorks to perform
    google search.

-   XploitHunt can search on zero day (onion website), too.

-   The tool also provides the benefit of accessing search results in a
    user-readable format, which contain the required details to assist the
    penetration tester in understanding whether the vulnerability is exploitable
    or not.

-   The tool is customizable and can be used with minimal human intervention.

**PREREQUISITES**

1.  **Kali Linux and Python required**

2.  **Repository Information:**

    git clone <https://github.com/uk45/XploitHunt.git>

3.  **Tor service installation:**

    sudo apt-get install tor

4.  **Installation:**

    cd XploitHunt

    pip install –r requirement.txt

    python XploitHunt.py –h

**Usage Examples:**

![XploitHunt-Help](https://i.ibb.co/g724kth/home.png)

1.  Normal scan without google and 0day search

    1.  Python XploitHunt.py –c CVE-2019-0708

        **Or**

    2.  Python XploitHunt.py –f \<filename\>.txt

2.  Scan with google mod enabled

    1.  Python XploitHunt.py –c CVE-2019-0708 –g on –l 5 –t 20

        **Or**

    2.  Python XploitHunt.py –f \<filename\>.txt –g on –l 5 –t 20

3.  Scan with google and 0day mode enabled

    1.  Python XploitHunt.py –c CVE-2019-0708 –g on –l 5 –t 20 –z on

        **Or**

    2.  Python XploitHunt.py –f \<filename\>.xls –g on –l 5 –t 20 –z on

**Blacklist the Host from google search:**

Open the “blacklist-host.txt” file and add the host name which you want to
blacklist.

![Blacklist-host-file](https://i.ibb.co/8bfgHzP/5.png)

**Google Dorks setup:**

Open the “google-payload” file and add the google dorks which you want (i.e.
intext=?) Or (i.e. intext:? Site:exploit-db.com)

![Google-Dorks-file](https://i.ibb.co/h22zC63/6.png)

**OutPut:**

![CVE-Exploit-Map.xlsx](https://i.ibb.co/nmKv9q2/4.png)

**LIMITIATIONS**

1.  Internet

2.  CVE-IDs to perform search

3.  It is possible that, requests on Google may block you, due to security
    reasons.
